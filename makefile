LDLIBS=-lpcap

all: arp-spoofing

arp-spoofing: main.o arphdr.o ethhdr.o ip.o mac.o arpspoof.o
	g++ -o arp-spoofing main.o arphdr.o ethhdr.o ip.o mac.o arpspoof.o -lpcap

main.o: ethhdr.h arphdr.h main.cpp
	g++ -std=c++11 -c -o main.o main.cpp

arphdr.o: arphdr.cpp arphdr.h mac.h	ip.h
	g++ -std=c++11 -c arphdr.cpp

ethhdr.o: ethhdr.cpp ethhdr.h mac.h
	g++ -std=c++11 -c ethhdr.cpp

mac.o: mac.cpp mac.h
	g++ -std=c++11 -c mac.cpp

ip.o: ip.cpp ip.h
	g++ -std=c++11 -c ip.cpp

arpspoof.o: arpspoof.cpp arpspoof.h
	g++ -std=c++11 -c arpspoof.cpp

clean:
	rm -f arp-spoofing *.o
