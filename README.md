# ip_stream_stats

I just need to monitor the various IP streams of my Home LAN without too much CPU power (in order to run on an small Armbian device). Tshark requires too much memory and cpu. Processing tcpdump output with a python script is also CPU intensive... and its is also a good exercise to play with libpcap in case I need for more specific stuff in future...



So, *ip_stream_stats* just performs the counting of the IP streams, dumping the stats periodically, using the lowest amount of CPU for the task.

I expect a python script to a use the raw output and perform more processing for higher level of formatting.

## Usage:

    usage: sudo ip_stream_stats (-i interface) [OPTIONS]
    OPTIONS:
      -i interface : network interface name where is capture frames (required)
      -p, --period SECONDS : Period between each stats dump (default 60s)
      -P, --promisc : turns the interface in promiscous mode
      -m, --min-pkts N : minimum number of packets (RX+TX) to take in count in stats
      -M, --min-bytes N : minimum number of bytes (RX+TX) to take in count in stats
      -F, --format FMT : Dump format (text or raw)
      -f, --filter PCAP_FILTER; 'man pcap-filter' for details of the syntax
      -c, --count N :  number of stats to dump before exit (default: don't stop)
      --debug
## Raw dumping format

Stats are written to stdout on a single line. Each stat item is separated with a single space ' '

```
[IP-A,IP-B,tx_pkts,tx_bytes,rx_pkts,rx_bytes] [[IP-A,IP-B,tx_pkts,tx_bytes,rx_pkts,rx_bytes]...]\n
```

TX means packets sent by A to B.