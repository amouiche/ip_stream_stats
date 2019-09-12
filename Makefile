
CFLAGS = -O1 -g -Wall
LDFLAGS = -lpcap

all: ip_stream_stats

ip_stream_stats: main.o
	g++  -o $@ $^ $(LDFLAGS)

%.o: %.cxx
	g++ $(CFLAGS) -o $@ -c $<
	
