LATEX=latex
BIBTEX=bibtex
DVIPDFM=dvipdfm
DVIPS=dvips

EXTRAFILES=$(wildcard *.tex)

N1=0main
BIBNAME=references.bib

all:
	pdflatex -shell-escape $(N1).tex
	bibtex $(N1)
	pdflatex -shell-escape $(N1).tex
	pdflatex -shell-escape $(N1).tex
	xpdf -remote xxx -reload
	
open:
	xpdf -remote xxx $(N1).pdf &

clean:
	\rm -rf *.aux *.dvi *.log *.bbl *.out *.blg *.ps *.pdf *~


#	bibtex $(BASENAME)
