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

// IPv6 address
typedef struct {
    uint16 set[8];
} ip6_addr;

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

// ipv6 header
typedef struct {
    uint32 vdeflow;
    uint16 p_len;
    uint8 next_h;
    uint8 hop_lim;
    ip6_addr src_6,
             dst_6;
} ip6_h;
#define IP6_VER(ip) (((ip->vdeflow) >> 28) & 0xf)

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

    pcap_h *header;

    header = (pcap_h *) malloc(sizeof(pcap_h));
    bzero((void *) header, sizeof(pcap_h));

    header->magic = (uint32)get32();
    header->ver_maj = (uint16)get16r();
    header->ver_min = (uint16)get16r();
    header->this_zone = (uint32)get32();
    header->sigfigs = (uint32)get32();
    header->snaplen = (uint32)flip32(get32());
    header->network = (uint32)get32();

    return header;
}

// populate packet (record) header
pcap_rec_h *packet_header() {
    pcap_rec_h *header;

    header = (pcap_rec_h *) malloc(sizeof(pcap_rec_h));

    header->sec = (uint32)get32();
    header->usec = (uint32)get32();
    header->in_len = (uint32)flip32(get32());
    header->len = (uint32)flip32(get32());
    return header;
}


// populate ethernet header (14 bytes)
eth_h *ethernet_header() {
    eth_h *header;
    header = (eth_h *)malloc(sizeof(eth_h));

    int i;
    for (i = 0; i < 6; i++)
        header->dst_eth[i] = (uint8)getchar();
    for (i = 0; i < 6; i++)
        header->src_eth[i] = (uint8)getchar();
    header->len_type = get16();

    return header;
}

// populate ip header
ip_h* ip_header() {
    int i;
    ip_h *header;
    header = (ip_h *)malloc(sizeof(ip_h));

    header->vhl = (uint8)getchar();
    header->dsf_ecn = (uint8)getchar();
    header->len = (uint16)get16();
    header->id = (uint16)get16();
    header->flag_off = (uint16)get16();
    header->ttl = (uint8)getchar();
    header->protcl = (uint8)getchar();
    header->check = (uint16)get16();

    for (i = 0; i < 4; i++)
        header->src_ip.oct[i] = (uint8)getchar();
    for (i = 0; i < 4; i++)
        header->dst_ip.oct[i] = (uint8)getchar();

    return header;
}

// populate ipv6 header
void ip6_header() {
    int i;
    ip6_h header;
    header.vdeflow = get32();
    header.p_len = get16();
    next_h = getchar();
    hop_lim = getchar();
    for (i = 0; i < 8; i++)
        header.src_6[i] = get16();
    for (i = 0; i < 8; i++)
        header.src_6[i] = get16();
    /* print ipv6 header */
    printf("IPv6 Header\nsrc: %04x", header.src_6[0]);
    for (i = 1; i < 8; i++)
        printf(":%04x", header.src_6[i]);
    printf("dst: %04x", header.dst_6[0]);
    for (i = 1; i < 8; i++)
        printf(":%04x", header.dst_6[i]);
    printf("\npayload length: %d, hop limit: %d\n",\
            header.p_len, header.hop_len);
    printf("next header: ");
    switch(header.next_h) {
        case 6:     // TCP
            printf("TCP\n");
            tcp_header();
            break;
        case 17:    // UDP
            printf("UDP\n");
            udp_header();
            break;
        default:
            printf("unknown\n");
            break;
    }


// populate udp header
udp_h* udp_header() {
    udp_h *header;
    header = (udp_h *)malloc(sizeof(udp_h));

    header->u_sport = (uint16)get16();
    header->u_dport = (uint16)get16();
    header->u_len = (uint16)get16();
    header->u_sum = (uint16)get16();

    return header;
}

// populate tcp header
tcp_h* tcp_header() {
    tcp_h *header;
    header = (tcp_h *)malloc(sizeof(tcp_h));

    header->t_sport = (uint16)get16();
    header->t_dport = (uint16)get16();
    header->t_seq = (uint32)get32();
    header->t_ack = (uint32)get32();
    header->t_hl_resv = (uint8)getchar();
    header->t_flags = (uint8)getchar();
    header->t_win = (uint16)get16();
    header->t_check = (uint16)get16();
    header->t_urg_p = (uint16)get16();

    return header;
}


int check_dns(udp_h *h, char *payload) {
    char *ptr;
    char hostname[257]; // domain name max length, RFC 1035, 1123, 2181
    int i;

    if (!h)
        return 0;
    if (h->u_sport != 53 && h->u_dport != 53)
        return 0;

    printf("DNS protocol, transaction #: 0x%04x\nType: ", *(uint16 *)payload);
    if (payload[3] & 0x80)
        printf("Response: ");
    else
        printf("Query: ");
    ptr = &payload[13];
    strcpy(hostname, ptr);
    for (i = 0; i < strlen(hostname); i++) {
        if (hostname[i] > 0 && hostname[i] < 6)
            hostname[i] = '.';
    }
    printf("%s", hostname);
    if (payload[3] & 0x80) {    // request, print IPv4 address
        ptr = &payload[13 + strlen(hostname) + 17];
        printf(" (%u.%u.%u.%u)", (uint8) *ptr, (uint8)*(ptr + 1), (uint8)*(ptr + 2), (uint8)*(ptr + 3));
    }
    printf("\n");
    return 1;
}

int check_tcp(tcp_h *h) {
    if (!h)
        return 0;

    printf("TCP frame: ");
    if (h->t_flags & T_SYN)
        printf("SYN");
    if (h->t_flags & T_ACK) {
        if (h->t_flags & T_SYN)
            printf("/");
        printf("ACK");
        printf(": 0x%08x", h->t_ack);
    }
    if (h->t_seq)
        printf(", Sequence: %d\n", h->t_seq);

    return 1;
}
