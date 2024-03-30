#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>


/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmp_id;     //Used for identifying request
  unsigned short int icmp_seq;    //Sequence number
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};

/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcpheader tcp;
        char payload[1500];
};

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    if (ip->iph_protocol == IPPROTO_TCP) { 
        struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl * 4);

        printf("Ethernet Header src mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
        printf("Ethernet Header dst mac: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

        printf("IP Header src ip: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("IP Header dst ip: %s\n", inet_ntoa(ip->iph_destip));

        printf("TCP Header src port: %d\n", ntohs(tcp->tcp_sport));
        printf("TCP Header dst port: %d\n", ntohs(tcp->tcp_dport));

        int tcp_data_offset = tcp->tcp_offx2 >> 4; 
        int tcp_data_size = header->caplen - sizeof(struct ethheader) - ip->iph_ihl * 4 - tcp_data_offset * 4;
        const u_char *tcp_data = packet + sizeof(struct ethheader) + ip->iph_ihl * 4 + tcp_data_offset * 4;
        printf("Message: ");
        if(tcp_data_size >100)
	{
		tcp_data_size = 100;
	}
        for (int i = 0; i < tcp_data_size; ++i) {
            printf("%c", isprint(tcp_data[i]) ? tcp_data[i] : '.');
        }
        printf("\n\n========================================\n\n");
    }
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

    pcap_loop(handle, 0, packet_capture, NULL);

    pcap_close(handle);

    return 0;
}
