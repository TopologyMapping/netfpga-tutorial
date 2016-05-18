///////////////////////////////////////////////////////////////////////////////
// vim:set shiftwidth=3 softtabstop=3 expandtab:
// $Id: module_template 2008-03-13 gac1 $
//
// Module: firewall.v
// Project: FIREWALL
// Description: define módulo para filtragem de pacotes pela porta de
// destino do pacote TCP/IP. As portas a ser filtradas são lidas por programas
// em espaço de usuário e gravadas na SRAM por este módulo. A SRAM
// é consultada a cada novo pacote. Pacotes que não sejam TCP/IP são
// encaminhados sem serem filtrados.
//
///////////////////////////////////////////////////////////////////////////////
`timescale 1ns/1ps

module firewall
   #(
      parameter DATA_WIDTH = 64,
      parameter CTRL_WIDTH = DATA_WIDTH/8,
      parameter SRAM_ADDR_WIDTH = 19,
      parameter SRAM_DATA_WIDTH = DATA_WIDTH+CTRL_WIDTH,
      parameter UDP_REG_SRC_WIDTH = 2
   )
   (
      input  [DATA_WIDTH-1:0]             in_data,
      input  [CTRL_WIDTH-1:0]             in_ctrl,
      input                               in_wr,
      output                              in_rdy,

      output reg [DATA_WIDTH-1:0]         out_data,
      output reg [CTRL_WIDTH-1:0]         out_ctrl,
      output reg                          out_wr,
      input                               out_rdy,

      // --- Register interface
      input                               reg_req_in,
      input                               reg_ack_in,
      input                               reg_rd_wr_L_in,
      input  [`UDP_REG_ADDR_WIDTH-1:0]    reg_addr_in,
      input  [`CPCI_NF2_DATA_WIDTH-1:0]   reg_data_in,
      input  [UDP_REG_SRC_WIDTH-1:0]      reg_src_in,

      output                              reg_req_out,
      output                              reg_ack_out,
      output                              reg_rd_wr_L_out,
      output  [`UDP_REG_ADDR_WIDTH-1:0]   reg_addr_out,
      output  [`CPCI_NF2_DATA_WIDTH-1:0]  reg_data_out,
      output  [UDP_REG_SRC_WIDTH-1:0]     reg_src_out,

      // --- SRAM arbiter interface
      output reg                          sram_rd_req,
      output reg [SRAM_ADDR_WIDTH-1:0]    sram_rd_addr,
      input [DATA_WIDTH-1:0]              sram_rd_data,
      input                               sram_rd_ack,
      input                               sram_rd_vld,

      output reg                          sram_wr_req,
      output reg [SRAM_ADDR_WIDTH-1:0]    sram_wr_addr,
      output reg [DATA_WIDTH-1:0]         sram_wr_data,
      input                               sram_wr_ack,

      // misc
      input                                reset,
      input                                clk
   );

   // Define the log2 function
   `LOG2_FUNC

   //------------------------- Signals-------------------------------
   
   localparam WAIT_PACKET =1;
   localparam WORD2_CHECK_IPV4 =2;
   localparam WORD3_CHECK_TCP_TTL =3;
   localparam WORD4_ADDR_CHKSUM =4;
   localparam WORD5_TCP_PORT =5;
   localparam CHECK_RULES = 6;
   localparam CHECK_PORTS = 7;
   localparam EMPTY_OUT_FIFO = 8;
   localparam PAYLOAD =9;
   localparam SRAM_PORTS_ADDR = 'h0;
   localparam NUM_WORDS_SALVAS = 4;

   localparam ICMP = 'h01;
   localparam TCP = 'h06;
   localparam UDP = 'h11;
   localparam SCTP = 'h84;

   wire [DATA_WIDTH-1:0]         in_fifo_data;
   wire [CTRL_WIDTH-1:0]         in_fifo_ctrl;

   wire                          in_fifo_nearly_full;
   wire                          in_fifo_empty;
   reg                           in_fifo_rd_en;

   reg [3:0]                     state, state_next;
      
   reg                           sram_wr_req_next, sram_rd_req_next;
   reg [DATA_WIDTH-1:0]          sram_wr_data_next;
 
   reg [SRAM_ADDR_WIDTH-1:0]     sram_wr_addr_next, sram_rd_addr_next;

   reg [31:0]                    num_TCP, num_TCP_next;

   reg [15:0]                    dst_port, dst_port_next;
   reg                           drop, drop_next;

   wire [31:0]                   dport1, dport2, dport3, dport4;
   wire                          addr_good, tag_hit;


   //Controle da fila de headers para modulo oq
   wire                             out_fifo_nearly_full, out_fifo_empty;
   reg                              out_fifo_rd_en, out_fifo_wr;
   wire [DATA_WIDTH+CTRL_WIDTH-1:0] out_fifo_dout;
   reg [DATA_WIDTH+CTRL_WIDTH-1:0]  in_out_fifo_dout;

   wire [15:0]                   chksum_cout;
   wire [16:0]                   chksum;
   //------------------------- Local assignments -------------------------------

   assign in_rdy     = !in_fifo_nearly_full;

   //------------------------- Modules-------------------------------

   fallthrough_small_fifo_old #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(3)
   ) input_fifo (
      .din           ({in_ctrl, in_data}),   // Data in
      .wr_en         (in_wr),                // Write enable
      .rd_en         (in_fifo_rd_en),        // Read the next word
      .dout          ({in_fifo_ctrl, in_fifo_data}),
      .full          (),
      .nearly_full   (in_fifo_nearly_full),
      .empty         (in_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );

   fallthrough_small_fifo_old #(
      .WIDTH(CTRL_WIDTH+DATA_WIDTH),
      .MAX_DEPTH_BITS(3)
   ) output_fifo (
      .din           (in_out_fifo_dout),   // Data in
      .wr_en         (out_fifo_wr),                // Write enable
      .rd_en         (out_fifo_rd_en),        // Read the next word
      .dout          (out_fifo_dout),
      .full          (),
      .nearly_full   (out_fifo_nearly_full),
      .empty         (out_fifo_empty),
      .reset         (reset),
      .clk           (clk)
   );


   generic_regs
   #(
      .UDP_REG_SRC_WIDTH   (UDP_REG_SRC_WIDTH),
      .TAG                 (`FIREWALL_BLOCK_ADDR),                 // Tag -- eg. MODULE_TAG
      .REG_ADDR_WIDTH      (`FIREWALL_REG_ADDR_WIDTH), // Width of block addresses -- eg. MODULE_REG_ADDR_WIDTH
      .NUM_COUNTERS        (0),                 // Number of counters
      .NUM_SOFTWARE_REGS   (4),                 // Number of sw regs
      .NUM_HARDWARE_REGS   (0)                  // Number of hw regs
   ) module_regs (
      .reg_req_in       (reg_req_in),
      .reg_ack_in       (reg_ack_in),
      .reg_rd_wr_L_in   (reg_rd_wr_L_in),
      .reg_addr_in      (reg_addr_in),
      .reg_data_in      (reg_data_in),
      .reg_src_in       (reg_src_in),

      .reg_req_out      (reg_req_out),
      .reg_ack_out      (reg_ack_out),
      .reg_rd_wr_L_out  (reg_rd_wr_L_out),
      .reg_addr_out     (reg_addr_out),
      .reg_data_out     (reg_data_out),
      .reg_src_out      (reg_src_out),

      // --- counters interface
      .counter_updates  (),
      .counter_decrement(),

      // --- SW regs interface
      .software_regs    ({dport1,dport2,dport3,dport4}),

      // --- HW regs interface
      .hardware_regs    (),

      .clk              (clk),
      .reset            (reset)
    );

   //------------------------- Logic-------------------------------
   //

   assign tag_hit = reg_addr_out[`UDP_REG_ADDR_WIDTH - 1:`FIREWALL_REG_ADDR_WIDTH]
      == `FIREWALL_BLOCK_ADDR;
   assign addr_good = reg_addr_out[`FIREWALL_REG_ADDR_WIDTH-1:0] >=
      `FIREWALL_DPORT1 && reg_addr_out[`FIREWALL_REG_ADDR_WIDTH] <= `FIREWALL_DPORT4;
   assign chksum = {1'b0,in_fifo_data[63:48]}+17'h100;
   assign chksum_cout = chksum[15:0]+{15'h0,chksum[16]};

   always @(*) begin
      sram_wr_data_next <= {dport4[15:0],dport3[15:0],dport2[15:0],dport1[15:0]};
      sram_wr_addr_next <= 'h0;
      if(tag_hit && addr_good && reg_ack_out) begin
         sram_wr_req_next <= 1;
      end
      else
         sram_wr_req_next <= 0;
   end

   always @(*) begin
      // Default values
      in_out_fifo_dout = {in_fifo_ctrl,in_fifo_data};
      {out_ctrl,out_data} = out_fifo_dout;
      in_fifo_rd_en = 0;
      out_wr = 0;
      
      out_fifo_wr = 0;
      out_fifo_rd_en = 0;

      sram_rd_req_next = 0;

      state_next = state;
      
      num_TCP = num_TCP_next;

      sram_rd_req_next = 0;
      sram_rd_addr_next = sram_rd_addr;

      dst_port_next = dst_port;
      drop_next = drop;

      case(state)
      WAIT_PACKET: begin
         if (!in_fifo_empty && out_rdy) begin
            in_fifo_rd_en = 1;
            out_fifo_wr = 1;
            //synthesis translate_off
            if(out_fifo_nearly_full) begin //se FIFO cheia
               $stop;
            end
            //synthesis translate_on
            if(in_fifo_ctrl == 'h0) begin
               state_next = WORD2_CHECK_IPV4;
            end else begin
               state_next = WAIT_PACKET;
            end
         end
         else
            state_next = WAIT_PACKET;
      end
      WORD2_CHECK_IPV4: begin
         if (!in_fifo_empty && out_rdy) begin
            if(in_fifo_data[31:16] != 16'h0800 ||
                  in_fifo_data[15:12] != 4'h4) begin
               state_next = EMPTY_OUT_FIFO;
            end
            else begin
               in_fifo_rd_en = 1;
               out_fifo_wr = 1;
               state_next = WORD3_CHECK_TCP_TTL;
            end
         end
         else
            state_next = WORD2_CHECK_IPV4;
      end
      EMPTY_OUT_FIFO: begin
         if(!out_rdy) 
            state_next = EMPTY_OUT_FIFO;
         else if(!out_fifo_empty) begin
            state_next = EMPTY_OUT_FIFO;
            out_wr = ~drop;
            out_fifo_rd_en = 1;
         end
         else
            state_next = PAYLOAD;
      end
      WORD3_CHECK_TCP_TTL: begin
         if (!in_fifo_empty && out_rdy) begin
            if(in_fifo_data[7:0] == TCP) begin
               in_fifo_rd_en = 1;
               out_fifo_wr = 1;
               in_out_fifo_dout = {in_fifo_ctrl,in_fifo_data[63:16],
                  in_fifo_data[15:8]-8'h1,in_fifo_data[7:0]};
               num_TCP_next = num_TCP + 'h1;
               state_next = WORD4_ADDR_CHKSUM;
            end
            else begin
               state_next = EMPTY_OUT_FIFO;
            end
         end
         else
            state_next = WORD3_CHECK_TCP_TTL;
      end
      WORD4_ADDR_CHKSUM: begin
         if (!in_fifo_empty && out_rdy) begin
            in_fifo_rd_en = 1;
            out_fifo_wr = 1;
            in_out_fifo_dout = {in_fifo_ctrl,chksum_cout,in_fifo_data[47:0]};
            state_next = WORD5_TCP_PORT;
         end
         else
            state_next = WORD4_ADDR_CHKSUM;
      end
      WORD5_TCP_PORT: begin
         if (!in_fifo_empty && out_rdy) begin
            dst_port_next = in_fifo_data[31:16];
            state_next = CHECK_RULES;
         end
         else
            state_next = WORD5_TCP_PORT;
      end
      CHECK_RULES: begin
         sram_rd_req_next = 1;
         sram_rd_addr_next = SRAM_PORTS_ADDR;
         state_next = CHECK_PORTS;
      end
      CHECK_PORTS: begin
         if (sram_rd_vld) begin
            if(sram_rd_data[15:0] == dst_port ||
                   sram_rd_data[31:16] == dst_port ||
                   sram_rd_data[47:32] == dst_port ||
                   sram_rd_data[63:48] == dst_port) begin
               drop_next = 1;
            end
            else
               drop_next = 0;
            state_next = EMPTY_OUT_FIFO;
         end
         else
            state_next = CHECK_PORTS;
      end
      PAYLOAD: begin
         //synthesis translate_off
         if(!out_fifo_empty) begin
            $stop;
         end
         //synthesis translate_on
         if (!in_fifo_empty && out_rdy) begin
            {out_ctrl,out_data} = {in_fifo_ctrl,in_fifo_data};
            in_fifo_rd_en = 1;
            out_wr = ~drop;
            if(in_fifo_ctrl != `IO_QUEUE_STAGE_NUM) begin
               state_next = PAYLOAD;
            end
            else if(in_fifo_ctrl == `IO_QUEUE_STAGE_NUM) begin
               out_wr = 0;
               in_fifo_rd_en = 0;
               drop_next = 0;
               state_next = WAIT_PACKET;
            end
         end
         else
            state_next = PAYLOAD;
      end
      endcase
   end

   always @(posedge clk) begin
      if(reset) begin
         sram_rd_req <= 0;
         state <= WAIT_PACKET;
         num_TCP <= 0;
         drop <= 0;
         dst_port <= 0;
      end
      else begin
         state <= state_next;
         sram_rd_req <= sram_rd_req_next;
         sram_rd_addr <= sram_rd_addr_next;
         sram_wr_data <= sram_wr_data_next;
         sram_wr_addr <= sram_wr_addr_next;
         sram_wr_req <= sram_wr_req_next;
         dst_port <= dst_port_next;
         drop <= drop_next;
      end
   end
endmodule
