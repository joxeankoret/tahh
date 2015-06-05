all:
	g++ cmdscan.c -o mycmdscan -Wall -Wno-unused-local-typedefs -ldl -g

clean:
	rm -f core ./mycmdscan

test:
	./mycmdscan -s `pwd`/eicar.com.txt
	./mycmdscan -s `pwd`/clean.txt

