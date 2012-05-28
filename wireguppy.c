/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */

/* Decode captured packet stream */

/*
 * Copyright © 2012 Joseph Lee <josephl@cs.pdx.edu>
 * Available under the MIT License
 * Wireguppy - CS 494 Assignment 1
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
    uint8   vhl; // ver = vhl >> 4 & 0xf; ihl = vhl 0xf
    uint8   dsf_ecn; // dsf: dsf_ecn >> 2 & 0x3f; ecn: dsf_ecn 0x3
    uint16  len,
            id,
            flag_off;
    uint8   ttl,
            protcl;
    uint16  check;
    ip_addr src_ip,
            dst_ip;
} ip_h;
#define IP_VER(ip) (((ip->vhl) >> 4) & 0xf)
#define IP_HL(ip) ((ip->vhl) & 0xf)

// tcp header
typedef struct {
    uint16  src_port,
            dst_port;
    uint32  seq,
            ack;
    uint8   hl_resv;
    uint8   flags;
    uint16  win,
            check,
            urg_p;
} tcp_h;
#define T_FIN 0x01
#define T_SYN 0x02
#define T_RST 0x04
#define T_PSH 0x08
#define T_ACK 0x10
#define T_URG 0x20
#define T_ECE 0x40
#define T_CWR 0x80
#define T_FLAGS (T_FIN|T_SYN|T_RST|T_PSH|T_ACK|T_URG|T_ECE|T_CWR)

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

pcap_h *global_header();


int main(int argc, char **argv) {
    int i;

    pcap_h *h;
    h = global_header();
    printf("%d!!!!\n", h->magic);

    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1;
    } else {
        assert(argc == 1);
    }
    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        for (i = 0; i < 6; i++)
            printf("h%d: %08x\n", i, get32());
        printf("\n");
    }
    while (1) {
        int lt, ch, paylen;
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            (void) get32();
            (void) get32();
            paylen = flip32(get32());
            printf("paylen: %d (%d)\n", paylen, flip32(get32()));
        }
        printf("src: ");
        print_ether();
        printf("\n");
        printf("dst: ");
        print_ether();
        printf("\n");
        lt = decode_length_type();
        if (lt == 0x0800)
            lt = show_ip();
        else if (lt <= 1500)
            show_payload(lt);
        else
            assert(0);
        assert(paylen >= lt - 14);
        if (!raw_mode) {
            paylen -= 14; /* ethernet header */
            paylen -= lt; /* IP packet */
            for (i = 0; i < paylen; i++)
                printf("pad%d: %02x\n", i, getchar() & 0xff);
        }
        ch = getchar();
        if (ch == EOF)
            break;
        (void) ungetc(ch, stdin);
        printf("\n");
    }
    return 0;
}


pcap_h *global_header() {

    pcap_h *header;
    header = (pcap_h *) malloc(sizeof(pcap_h));

    bzero((void *) header, sizeof(pcap_h));

    return header;
}
