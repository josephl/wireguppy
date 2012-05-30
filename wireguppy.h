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

int ip_header();
int ip6_header();
void ethernet_header(int);
void udp_header();
void tcp_header(unsigned int);
void check_dns(char *);

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
#define IP_VER(ip) (((ip.vhl) >> 4) & 0xf)
#define IP_HL(ip) ((ip.vhl) & 0xf)

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
#define T_HL(tcp) (((tcp.t_hl_resv) >> 4) & 0xf)
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
    // printf("length/type: %04x\n", length_type);
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

/* populate packet (record) header
 */
pcap_rec_h* packet_header() {
    pcap_rec_h *hdr;
    hdr = (pcap_rec_h *) malloc(sizeof(pcap_rec_h));

    hdr->sec = (uint32)get32();
    hdr->usec = (uint32)get32();
    hdr->in_len = (uint32)flip32(get32());
    hdr->len = (uint32)flip32(get32());

    return hdr;
}


// obtain ethernet state from stdin
void ethernet_header(int pkt_len) {
    int i,
        pad;
    eth_h hdr;

    /* read from stdin */
    for (i = 0; i < 6; i++)
        hdr.dst_eth[i] = (uint8)getchar();
    for (i = 0; i < 6; i++)
        hdr.src_eth[i] = (uint8)getchar();
    hdr.len_type = (uint16) decode_length_type();
    pad = pkt_len - 14;     // total pkt length - eth hdr len

    /* print ethernet header info */
    printf(">>> ethernet frame\ndst: %02x", hdr.dst_eth[0]);
    for (i = 1; i < 6; i++)
        printf(":%02x", hdr.dst_eth[i]);
    printf("\nsrc: %02x", hdr.src_eth[0]);
    for (i = 1; i < 6; i++)
        printf(":%02x", hdr.src_eth[i]);
    printf("\nlength/type: %04x\n", hdr.len_type);

    /* determine following frame from len_type */
    switch(hdr.len_type) {
        case 0x0800:            // ipv4
            pad -= ip_header();
            break;
        case 0x8dd:             // ipv6
            pad -= ip6_header();
            break;
        case 0x0806:            // arp
            // TODO: handle arp packet
            assert(0);
            break;
        default:
            if (hdr.len_type <= 1536) { // length
                show_payload(hdr.len_type);
                pad -= hdr.len_type;
            }
            else {
                fprintf(stderr, "undefined ethernet length/type: %04x",
                        hdr.len_type);
                // dump payload based on packet length
                assert(0);
            }
            break;
    }
    /* padding */
    if (!raw_mode) {
        for (i = 0; i < pad; i++)
            printf("pad%02d: %02x\n", i, getchar());
    }
}


/* read IPv4 header from stdin
 * return length of entire IP packet, including header
 */
int ip_header() {
    int i;
    ip_h hdr;

    /* read from stdin, populate header */
    hdr.vhl = (uint8)getchar();
    hdr.dsf_ecn = (uint8)getchar();
    hdr.len = (uint16)get16();
    hdr.id = (uint16)get16();
    hdr.flag_off = (uint16)get16();
    hdr.ttl = (uint8)getchar();
    hdr.protcl = (uint8)getchar();
    hdr.check = (uint16)get16();
    for (i = 0; i < 4; i++)
        hdr.src_ip.oct[i] = (uint8)getchar();
    for (i = 0; i < 4; i++)
        hdr.dst_ip.oct[i] = (uint8)getchar();

    /* print IPv4 header */
    printf(">>> IPv4 frame\n");
    printf("src addr: %u", hdr.src_ip.oct[0]);
    for (i = 1; i < 4; i++)
        printf(".%u", hdr.src_ip.oct[i]);
    printf("\ndst addr: %u", hdr.dst_ip.oct[0]);
    for (i = 1; i < 4; i++)
        printf(".%u", hdr.dst_ip.oct[i]);
    printf("\nlength: %u, id: %u, time-to-live: %u\n",
            hdr.len, hdr.id, hdr.ttl);

    switch(hdr.protcl) {
        case 6:     // tcp
            tcp_header(hdr.len - (IP_HL(hdr) * 4));
            break;
        case 17:    // udp
            udp_header();
            break;
        case 4:     // ipv4-in-ipv4 (tunneling)
            ip_header();
            break;
        default:
            fprintf(stderr, "unknown ipv4 protocol: %u\n", hdr.protcl);
            assert(0);
            break;
    }

    return hdr.len;
}

/* parse ipv6 header
 * return full length of ipv6 packet, including header
 */
int ip6_header() {
    int i;
    ip6_h hdr;
    hdr.vdeflow = get32();      // meh. fix?
    hdr.p_len = get16();
    hdr.next_h = getchar();
    hdr.hop_lim = getchar();
    for (i = 0; i < 8; i++)
        hdr.src_6.set[i] = get16();
    for (i = 0; i < 8; i++)
        hdr.src_6.set[i] = get16();
    /* print ipv6 header */
    printf("IPv6 hdr\nsrc: %04x", hdr.src_6.set[0]);
    for (i = 1; i < 8; i++)
        printf(":%04x", hdr.src_6.set[i]);
    printf("dst: %04x", hdr.dst_6.set[0]);
    for (i = 1; i < 8; i++)
        printf(":%04x", hdr.dst_6.set[i]);
    printf("\npayload length: %d, hop limit: %d\n",\
            hdr.p_len, hdr.hop_lim);
    printf("next hdr: ");
    switch(hdr.next_h) {
        case 6:     // TCP
            printf("TCP\n");
            tcp_header(hdr.p_len);
            break;
        case 17:    // UDP
            printf("UDP\n");
            udp_header();
            break;
        default:
            printf("unknown\n");
            break;
    }
    return hdr.p_len + 40;
}


// populate udp header
void udp_header() {
    int i;
    udp_h hdr;
    char *payload;
    payload = NULL;

    /* read in udp hdr info */
    hdr.u_sport = (uint16)get16();
    hdr.u_dport = (uint16)get16();
    hdr.u_len = (uint16)get16();
    hdr.u_sum = (uint16)get16();

    /* print udp header info */
    printf(">>> UDP frame\n");
    printf("src port: %u\ndst port: %u\n", hdr.u_sport, hdr.u_dport);

    /* get payload */
    payload = (char *)malloc(sizeof(char) * (hdr.u_len + 1));
    for (i = 0; i < hdr.u_len; i++)
        payload[i] = getchar();
    payload[hdr.u_len] = '\0';

    /* check for DNS packet */
    if (hdr.u_sport == 53 || hdr.u_dport == 53)
        check_dns(payload);
    else
        printf("payload length: %u\n%s", hdr.u_len, payload);

    if (payload)    // payload length
        free(payload);
}

/* read in TCP header, payload
 * arg: read in length of TCP header, as
 * TCP frame does not supply payload length
 */
void tcp_header(unsigned int ip_len) {
    int i,
        paylen;     // payload length
    tcp_h hdr;
    char *payload;
    payload = NULL;

    hdr.t_sport = (uint16)get16();
    hdr.t_dport = (uint16)get16();
    hdr.t_seq = (uint32)get32();
    hdr.t_ack = (uint32)get32();
    hdr.t_hl_resv = (uint8)getchar();
    hdr.t_flags = (uint8)getchar();
    hdr.t_win = (uint16)get16();
    hdr.t_check = (uint16)get16();
    hdr.t_urg_p = (uint16)get16();

    printf(">>> TCP frame: ");

    /* syn/ack-ness */
    if (hdr.t_flags & T_SYN)
        printf("SYN");
    if (hdr.t_flags & T_ACK) {
        if (hdr.t_flags & T_SYN)
            printf("/");
        printf("ACK");
        printf(": 0x%08x", hdr.t_ack);
    }
    if (hdr.t_seq)
        printf(", Sequence: %d\n", hdr.t_seq);

    /* read in payload */
    paylen = ip_len - T_HL(hdr) * 4;
    // payload = (char *)malloc(sizeof(char) * (ip_len - T_HL(&hdr) * 4 + 1));
    payload = (char *)malloc(sizeof(char) * paylen + 1);
    for (i = 0; i < paylen; i++)
        payload[i] = getchar();
    payload[paylen] = '\0';

    /* check for DNS packet */
    if (hdr.t_sport == 53 || hdr.t_dport == 53)
        check_dns(payload);
    else
        printf("payload length: %u\n%s", paylen, payload);

    if (payload)
        free(payload);
}


void check_dns(char *payload) {
    char *ptr;
    char hostname[257]; // domain name max length, RFC 1035, 1123, 2181
    int i;

    printf("DNS protocol, transaction #: 0x%04x\nType: ", *(uint16 *)payload);
    if (payload[3] & 0x80)
        printf("Response: ");
    else
        printf("Query: ");
    ptr = &payload[13];
    strcpy(hostname, ptr);

    /* replace unprintable delims w/dots in ip addr */
    for (i = 0; i < strlen(hostname); i++) {
        if (hostname[i] > 0 && hostname[i] < 6)
            hostname[i] = '.';
    }

    printf("%s", hostname);
    if (payload[3] & 0x80) {    // request, print IPv4 address
        ptr = &payload[13 + strlen(hostname) + 17];
        printf(" (%u.%u.%u.%u)",\
                (uint8) *ptr, (uint8)*(ptr + 1),\
                (uint8)*(ptr + 2), (uint8)*(ptr + 3));
    }
    printf("\n");
}

// void check_tcp(tcp_h hdr) {
// 
//     printf("TCP frame: ");
//     if (hdr.t_flags & T_SYN)
//         printf("SYN");
//     if (hdr.t_flags & T_ACK) {
//         if (hdr.t_flags & T_SYN)
//             printf("/");
//         printf("ACK");
//         printf(": 0x%08x", hdr.t_ack);
//     }
//     if (hdr.t_seq)
//         printf(", Sequence: %d\n", hdr.t_seq);
// 
//     return 1;
// }
