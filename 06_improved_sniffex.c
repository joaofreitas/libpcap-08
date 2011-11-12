/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap and libnet.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * Same description of 05_sniffex.c here...
 * 
 ****************************************************************************
 * 
 * Example compiler command-line for GCC:
 *   gcc 06_improved_sniffex.c -lpcap -lnet -o 06_improved_sniffex -g -Wall
 * 
 ****************************************************************************
 *
 * And here too...
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define IP_HL(ip)               (((ip)->ip_v << 4 | (ip)->ip_hl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

int
print_tcp_header(const struct libnet_tcp_hdr *tcp);

int
print_udp_header(const struct libnet_udp_hdr *udp);

void
print_payload(const char *payload, int size_payload);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [interface]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

return;
}

/*
 * print tcp header and return the size of packet
 */
int
print_tcp_header(const struct libnet_tcp_hdr *tcp)
{
	int size_tcp;

	size_tcp = tcp->th_off * 4;
	
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	printf("   Seq Num: %u\n", tcp->th_seq);
	printf("   Ack: %u\n", tcp->th_ack);
	printf("   Size tcp packet: %d\n", size_tcp);
	
	return size_tcp;
	
}

/*
 * print udp header and return the size of packet
 */
int
print_udp_header(const struct libnet_udp_hdr *udp)
{
	int size_udp;

	size_udp = udp->uh_ulen;
	
	printf("   Src port: %d\n", ntohs(udp->uh_sport));
	printf("   Dst port: %d\n", ntohs(udp->uh_dport));
	printf("   Size udp packet: %d\n", size_udp);
	
	return size_udp;
}

/*
 * print only payload size, because payload is too long.
 */
void
print_payload(const char *payload, int size_payload)
{
	if (size_payload > 0) {
		printf("   Payload (%d bytes)\n", size_payload);
	}
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	/* declare pointers to packet headers */
	const struct libnet_ethernet_hdr *ethernet;  /* The ethernet header [1] */
	const struct libnet_ipv4_hdr *ip;              /* The IP header */
	const struct libnet_tcp_hdr *tcp;		/* The TCP header */
	const struct libnet_udp_hdr *udp;		/* The UDP header */
	const char *payload;					/* The Payload */
	
	static int count = 1;                   /* packet counter */
	int size_ip;
	int size_transport_layer;
	int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
	ethernet = (struct libnet_ethernet_hdr*)(packet);
	printf("Ethernet type: 0x0%x\n", ntohs(ethernet->ether_type));
	
	/* define/compute ip header offset */
	ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			
			tcp = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + size_ip);
			size_transport_layer = print_tcp_header(tcp);
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			
			udp = (struct libnet_udp_hdr*)(packet + LIBNET_ETH_H + size_ip);
			size_transport_layer = print_udp_header(udp);
			break;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	payload = (char *)(packet + LIBNET_ETH_H + size_ip + size_transport_layer);	/* define/compute tcp payload (segment) offset */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_transport_layer);			/* compute tcp payload (segment) size */
	print_payload(payload, size_payload);
	
	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */

	print_app_banner();

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

