LATEX=latex
BIBTEX=bibtex
DVIPDFM=dvipdfm
DVIPS=dvips

N1=main
BIBNAME=references.bib

all:
	pdflatex -shell-escape $(N1).tex
	bibtex $(N1)
	pdflatex -shell-escape $(N1).tex
	pdflatex -shell-escape $(N1).tex
	xpdf -remote tut -reload
	
open:
	xpdf -remote tut $(N1).pdf &

clean:
	\rm -rf *.aux *.dvi *.log *.bbl *.out *.blg *.ps *.pdf *~
