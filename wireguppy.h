#include <stdio.h>
#include <stdlib.h>

#define WORD_LEN 4  // length of word, in bytes
#define ETH_HLEN 14 // length of ethernet header
#define ETH_TCP_T 6
#define ETH_UDP_T 17
#define UDP_HLEN 8

typedef u_int32_t uint32;
typedef u_int16_t uint16;
typedef u_int8_t uint8;

// IPv4 address
typedef struct {
    uint8  oct[4];
} ip_addr;

// global pcap header
typedef struct {
    uint32  magic;
    uint16  ver_maj,
            ver_min;
    int     this_zone;
    uint32  sigfigs,
            snaplen,
            network;
} pcap_h;

// pcap record header
typedef struct {
    uint32  sec,
            usec,
            in_len,
            len;
} pcap_rec_h;

// ethernet header
typedef struct {
    uint8   dst_eth[6],
            src_eth[6];
    uint16  len_type;
} eth_h;

// ipv4 header
typedef struct {
    uint8   vhl;
    uint8   dsf_ecn;
    uint16  len;
    uint16  id;
    uint16  flag_off;
    uint8   ttl;
    uint8   protcl;
    uint16  check;
    ip_addr src_ip,
            dst_ip;
} ip_h;
#define IP_VER(ip) (((ip->vhl) >> 4) & 0xf)
#define IP_HL(ip) ((ip->vhl) & 0xf)

// tcp header
typedef struct {
    uint16  t_sport,
            t_dport;
    uint32  t_seq,
            t_ack;
    uint8   t_hl_resv;
    uint8   t_flags;
    uint16  t_win,
            t_check,
            t_urg_p;
} tcp_h;
#define T_HL(tcp) (((tcp->t_hl_resv) >> 4) & 0xf)
#define T_FIN 0x01
#define T_SYN 0x02
#define T_RST 0x04
#define T_PSH 0x08
#define T_ACK 0x10
#define T_URG 0x20
#define T_ECE 0x40
#define T_CWR 0x80
#define T_FLAGS (T_FIN|T_SYN|T_RST|T_PSH|T_ACK|T_URG|T_ECE|T_CWR)

// udp header
typedef struct {
    uint16  u_sport,
            u_dport,
            u_len,
            u_sum;
} udp_h;

void print_ether() {
    int i;
    printf("%02x", getchar());
    for (i = 1; i < 6; i++)
        printf(":%02x", getchar());
}

int get16(void) {
    int b1 = getchar();
    int b2 = getchar();
    return ((b1 << 8) & 0xff00) | (b2 & 0xff);
}
int get16r(void) {
    int b1 = getchar();
    int b2 = getchar();
    return ((b2 << 8) & 0xff00) | (b1 & 0xff);
}


int get32(void) {
    int b1 = getchar();
    int b2 = getchar();
    int b3 = getchar();
    int b4 = getchar();
    return
        ((b1 << 24) & 0xff000000) |
        ((b2 << 16) & 0xff0000) |
        ((b3 << 8) & 0xff00) |
        (b4 & 0xff);
}

int flip32(int x) {
    return
        ((x >> 24) & 0xff) |
        ((x >> 8) & 0xff00) |
        ((x << 8) & 0xff0000) |
        ((x << 24) & 0xff000000);
}

int decode_length_type() {
    int length_type = get16();
    if (length_type == 0x8100) {
        printf("VLAN: %04x\n", get16());
        length_type = get16();
    }
    printf("length/type: %04x\n", length_type);
    return length_type;
}

/* ASSIGNMENT: MODIFY THIS TO PRINT INFORMATION ABOUT
   ENCAPSULATED PAYLOAD. */
int show_ip() {
    int i, length;
    (void) get16();
    length = get16();
    printf("IP: length %d\n", length);
    for (i = 0; i < length - 4; i++)
        (void) getchar();
    return length;
}

void show_payload(int lt) {
    int i;
    for (i = 0; i < lt; i++)
        getchar();
}

int raw_mode = 0;

// populate global packet header
pcap_h *global_header() {

    int i;
    pcap_h *header;
    uint32 *ptr;

    header = (pcap_h *) malloc(sizeof(pcap_h));
    bzero((void *) header, sizeof(pcap_h));
    ptr = (uint32 *) header;

    for (i = 0; i < 6; i++, ptr++)
        *ptr = get32();

    return header;
}

// populate packet (record) header
pcap_rec_h *packet_header() {
    int i;
    pcap_rec_h *header;
    uint32 *ptr;

    header = (pcap_rec_h *) malloc(sizeof(pcap_rec_h));
    bzero((void *) header, sizeof(pcap_rec_h));
    ptr = (uint32 *) header;

    for (i = 0; i < 4; i++, ptr++) {
        if (i < 2)
            *ptr = get32();
        else
            *ptr = flip32(get32());
    }

    return header;
}


// populate ethernet header (14 bytes)
eth_h *ethernet_header() {
    int i;
    eth_h *header;
    uint8 *ptr;
    uint16 temp;

    header = (eth_h *)malloc(sizeof(eth_h));
    ptr = (uint8 *) header;

    for (i = 0; i < 14; i++, ptr++)
        *ptr = (uint8)getchar();
    // switch len_type endian
    temp = (header->len_type & 0xff) << 8;
    temp |= ((header->len_type & 0xff00) >> 8) & 0xff;
    header->len_type = temp;

    return header;
}

// populate ip header
ip_h* ip_header() {
    int i;
    ip_h *header;
    uint16 *ptr;

    header = (ip_h *)malloc(sizeof(ip_h));
    ptr = (uint16 *) header;

    for (i = 0; i < 10; i++, ptr++) {
        if (i % 2 == 0)
            *ptr = get16r();
        else
            *ptr = get16();
    }

    return header;
}

// populate udp header
udp_h* udp_header() {
    int i;
    udp_h *header;

    uint16 *ptr;
    header = (udp_h *)malloc(sizeof(udp_h));
    ptr = (uint16 *) header;

    for (i = 0; i < 4; ++i, ptr++)
        *ptr = get16();

    return header;
}

// populate tcp header
tcp_h* tcp_header() {
    int i;
    tcp_h *header;
    uint16 *ptr;
    header = (tcp_h *)malloc(sizeof(tcp_h));
    ptr = (uint16 *) header;

    for (i = 0; i < 10; i++, ptr++) {
        if (i < 5)
            *ptr = (uint16)get16();
        else
            *ptr = (uint16)get16r();
    }

    return header;
}
