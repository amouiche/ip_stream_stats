/*
 *  Basic IP packets counting tool.
 *  Accumulate the number of bytes and frames received/sent between 2 IP addresses.
 *  Display stats periodically.
 *
 *  Copyright Arnaud Mouiche 2019
 *  License: MIT
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <map>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <getopt.h>
#include <string.h>

struct ip_stats {
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint32_t rx_pkts;
    uint32_t tx_pkts;
};


/* stores IP address couple (2x2=32bits) as a single u64.
 * By convention,
 * - byte order is CPU order
 * - highest IP address is first in the MSB part of the u64
 * - stats associated to a u64 are seen from the highest IP address point of view
 */
uint64_t couple2single(uint32_t a, uint32_t b) { return ((uint64_t)b) | (((uint64_t) a)<<32); }

uint32_t single2high(uint64_t s) { return s >> 32; }
uint32_t single2low(uint64_t s) { return s & 0xFFFFFFFFU; }



/* global dictionary where are stored the statistics */
std::map<uint64_t,struct ip_stats> stats;

 
/*
 * Print a buffer content to stdout
 */
void dump_buff(const uint8_t *data, unsigned size)
{
    unsigned p=0;
    while (p < size) {
        if ((p & 15) == 0)
            printf("%04x:", p);
        printf(" %02x", data[p]);
        p++;
        if ((p & 15) == 0)
            puts("");
    }
    if (p & 15) puts("");
}




void usage(void) {
    puts(
        "usage: sudo ip_stream_stats (-i interface) [OPTIONS]\n"
        "OPTIONS:\n"
        "  -i interface : network interface name where is capture frames (required)\n"
        "  -p, --period SECONDS : Period between each stats dump (default 60s)\n"
        "  -P, --promisc : turns the interface in promiscous mode\n"
        "  -m, --min-pkts N : minimum number of packets (RX+TX) to take in count in stats\n"
        "  -M, --min-bytes N : minimum number of bytes (RX+TX) to take in count in stats\n"
        "  -F, --format FMT : Dump format (text or raw)\n"
        "  -f, --filter PCAP_FILTER; 'man pcap-filter' for details of the syntax\n"
        "  -c, --count N :  number of stats to dump before exit (default: don't stop)\n"
        "  --debug\n"
        );
}

pcap_t* pcap;

/* global command line options */
bool stats_dump = false;  /* true if time to dump the stats */

bool opt_debug = false;
const char *opt_if = nullptr;
bool opt_promisc = false;
unsigned opt_p = 60;
unsigned opt_min_pkts = 0;
unsigned opt_min_bytes = 0;

enum format_e {
    F_TEXT, /* human readable array */
    F_RAW, /* one line with space separated items, each items = "A_addr,B_addr,A_tx_bytes,A_tx_pkts,A_rx_bytes,A_rx_pkts" */
} opt_format = F_TEXT;

const char *opt_filter = nullptr;
int opt_count = 0;

enum {
    OPT_debug = 256,
};

const struct option options[] = {
	{ "period", 1, NULL, 'p' },
	{ "promisc", 0, NULL, 'P' },  
	{ "min-pkts", 1, NULL, 'm' },  
	{ "min-bytes", 1, NULL, 'M' },  
	{ "format", 1, NULL, 'F' },  
	{ "filter", 1, NULL, 'f' },
	{ "count", 1, NULL, 'c' },
	{ "debug", 0, NULL, OPT_debug },
	{ NULL, 0, NULL, 0 }
};



/*
 * Parse the command line parameters
 */
void parse_opt(int argc, char* const*argv) 
{
    int result;
	int opt_index;
	while (1) {
	    if ((result = getopt_long( argc, argv, "i:p:Pm:M:f:F:c:", options, &opt_index )) == EOF) break;
	    switch (result) {
	    case '?': 
		    usage();
			exit(1);
			break;
		case 'i':
		    opt_if = optarg;
		    break;
	    case 'p':
	        opt_p = atoi(optarg);
	        break;
	    case 'm':
	        opt_min_pkts = atoi(optarg);
	        break;
	    case 'M':
	        opt_min_bytes = atoi(optarg);
	        break;
	    case 'f':
	        opt_filter = optarg;
	        break;
	    case 'c':
	        opt_count = atoi(optarg);
	        break;
	    case 'F':
	        if (!strcmp(optarg, "text")) {
	            opt_format = F_TEXT;
	        } else if (!strcmp(optarg, "raw")) {
	            opt_format = F_RAW;
	        } else {
	            fprintf(stderr, "Invalid -f,--format option\n");
	            exit(1);
	        }
	        opt_min_bytes = atoi(optarg);
	        break;
	    case 'P':
	        opt_promisc = true;
	        break;
	    case OPT_debug:
	        opt_debug = true;
	        break;
	    }
	}
	argv += optind;
	
	if (!opt_if) {
	    fprintf(stderr, "Network interface not specified. (see -i)\n");
	    exit(1);
	}
}



/*
 *  IP addr in host order uint32_t to string
 */
void atop(uint32_t addr, char *dst, socklen_t size) {
    struct in_addr ip = {htonl(addr)};
    inet_ntop(AF_INET, &ip, dst, size);
}




void do_stats_dump(void) {
    if (opt_format == F_TEXT) {
        printf("-------------------------------------------------------------------------\n");
        printf("                                                TX                RX\n");
    }
    bool first_item = true;
    for (const auto &i :stats) {
        const struct ip_stats &s = i.second;
        
        if (s.tx_pkts + s.rx_pkts < opt_min_pkts) continue;
        if (s.tx_bytes + s.rx_bytes < opt_min_bytes) continue;
        
        uint32_t a = single2high(i.first);
        uint32_t b = single2low(i.first);
        
        char a_addr[16];
        char b_addr[16];
        atop(a, a_addr, sizeof(a_addr));
        atop(b, b_addr, sizeof(b_addr));
        
        if (opt_format == F_TEXT) {
            printf("%16s => %16s :   %9" PRIu64 "  %4u - %9" PRIu64 " %4u\n", a_addr, b_addr, s.tx_bytes, s.tx_pkts, s.rx_bytes, s.rx_pkts);
        }
        if (opt_format == F_RAW) {
            if (!first_item) 
                putchar(' ');
            printf("%s,%s,%" PRIu64 ",%u,%" PRIu64 ",%u", a_addr, b_addr, s.tx_bytes, s.tx_pkts, s.rx_bytes, s.rx_pkts);
        }
        first_item = false;
    }
    if (opt_format == F_RAW) 
        puts("");
        
    stats.clear();
}


void alarm_handler(int sig)
{
    /* set the next alarm */
    alarm(opt_p);
    
    /* Force exit of pcap_next_ex() loop.
     * Performs dumping of stats in the main loop to avoid possible races.
     */
    stats_dump = true;
    pcap_breakloop(pcap); 
}


int main(int argc, char* const*argv)
{    
    char errbuf[PCAP_ERRBUF_SIZE];
    int r;
	bpf_u_int32 mask;
	bpf_u_int32 net;
    struct bpf_program filter = {0};
    
    parse_opt(argc, argv);
    
    if (pcap_lookupnet(opt_if, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", opt_if);
		 net = 0;
		 mask = 0;
	}
    pcap = pcap_create(opt_if, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap_create failure.\n");
        exit(1);
    }
    
    r = pcap_set_promisc(pcap, opt_promisc);
    if (r) {
        fprintf(stderr, "pcap_set_promisc failure.\n");
        exit(1);
    }
    
    r = pcap_set_snaplen(pcap, 64);
    if (r) {
        fprintf(stderr, "pcap_set_snaplen failure.\n");
        exit(1);
    }

    r = pcap_set_timeout(pcap, 1000);
    if (r) {
        fprintf(stderr, "pcap_set_timeout failure.\n");
        exit(1);
    }
     
    r = pcap_activate(pcap);
    if (r) {
        fprintf(stderr, "pcap_activate failure.\n");
        exit(1);
    }
    
    if (opt_filter) {
        r = pcap_compile(pcap, &filter, opt_filter, 1, mask);
        if (r) {
            fprintf(stderr, "pcap_compile failure. Invalid filter.\n");
            exit(1);
        }
        r = pcap_setfilter(pcap, &filter);
        if (r) {
            fprintf(stderr, "pcap_setfilter failure.\n");
            exit(1);
        }
    }
    
    /* setup the recursive Alarm for stats dumping */
    struct sigaction act = {0};
    act.sa_handler = alarm_handler;
    act.sa_flags = 0;
    sigaction(SIGALRM, &act, NULL);
    alarm(opt_p);
    
    /* packet capture and counting */
    while (1) {
        struct pcap_pkthdr *h;
        const u_char *data;
        
        
        if (stats_dump) {
            stats_dump = false;
            do_stats_dump();
            if (opt_count > 0) {
                if (--opt_count == 0) break;
            }
        }

        r = pcap_next_ex(pcap, &h, &data);
        if (r == -1) {
            fprintf(stderr, "pcap_next error: %s\n", pcap_geterr(pcap));
            break;
        }
        if (r != 1) {
            /* alarm or timeout */
            continue;
        }
        
        if (opt_debug) {
            printf("next: data=%p, caplen=%u, len=%u\n", data, h->caplen, h->len);
            if (data) {
                dump_buff(data, h->caplen);
            }
        }
        
        struct ether_header *eptr = (struct ether_header *) data;
        if (ntohs(eptr->ether_type) != ETHERTYPE_IP) {
            //printf("  Not IP\n");
            continue;
        }
        struct ip* ipptr = (struct ip*)(data + sizeof(*eptr));
        struct in_addr ip_src = ipptr->ip_src;
        struct in_addr ip_dst = ipptr->ip_dst;
        
        char asrc[16];
        char adst[16];
        inet_ntop(AF_INET, &ip_src, asrc, sizeof(asrc));
        inet_ntop(AF_INET, &ip_dst, adst, sizeof(adst));
        uint32_t hsrc = ntohl(ip_src.s_addr);
        uint32_t hdst = ntohl(ip_dst.s_addr);
        uint64_t handle;
        unsigned data_size = h->len - sizeof(struct ether_header *) - sizeof(struct ip*); /* todo: better computation */

        if (opt_debug) {
            printf("%s => %s %u\n", asrc, adst, data_size);
        }
        
        struct ip_stats s = {0};
        if (hsrc > hdst) {
            handle = couple2single(hsrc, hdst);
            s.tx_bytes += data_size;
            s.tx_pkts += 1;
        } else {
            handle = couple2single(hdst, hsrc);
            s.rx_bytes += data_size;
            s.rx_pkts += 1;
       }
        
        auto i = stats.find(handle);
        if (i != stats.end()) {
            i->second.tx_bytes += s.tx_bytes;
            i->second.rx_bytes += s.rx_bytes;
            i->second.tx_pkts += s.tx_pkts;
            i->second.rx_pkts += s.rx_pkts;    
        } else {
            stats[handle] = s;
        }    
    }
    
    return 0;
}
