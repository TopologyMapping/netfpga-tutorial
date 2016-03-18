LATEX=latex
BIBTEX=bibtex
DVIPDFM=dvipdfm
DVIPS=dvips

N1=main
BIBNAME=references.bib

UNAME := $(shell uname)

all: compile open

compile:
	pdflatex -shell-escape $(N1).tex
	bibtex $(N1)
	pdflatex -shell-escape $(N1).tex
	pdflatex -shell-escape $(N1).tex
	
open:
ifeq ($(UNAME),Darwin)
	open -a Preview.app $(N1).pdf 
endif
ifeq ($(UNAME),Linux)
	xpdf -remote tut $(N1).pdf &
endif

clean:
	\rm -rf *.aux *.dvi *.log *.bbl *.out *.blg *.ps *.pdf *~
