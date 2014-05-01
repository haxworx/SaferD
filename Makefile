FLAGS=-g -pedantic -std=gnu99 -Wall -W 
CXX=gcc
LIBS=-lcrypto
PROGNAME=saferd
OUTFILE=saferd
VERSION=002
CPP=-DVERSION=$(VERSION)


default:
	$(CXX) $(FLAGS) $(CPP) $(LIBS) saferd.c -o $(OUTFILE)
clean:
	rm $(OUTFILE)
