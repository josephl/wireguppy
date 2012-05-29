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
#include "wireguppy.h"


int main(int argc, char **argv) {
    int i;
    pcap_h     *global_hdr;     // packet headers
    pcap_rec_h *packet_hdr;
    eth_h      *eth_hdr;
    ip_h       *ip_hdr;
    tcp_h      *tcp_hdr;
    udp_h      *udp_hdr;
    char *payload;      // payload
    payload = NULL;

    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1;
    } else {
        assert(argc == 1);
    }
    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        /* Get Global PCAP header */
        global_hdr = global_header();
    }
    while (1) {
        int lt, ch,
            paylen;
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            packet_hdr = packet_header();
            printf("length: %d (%d)\n", packet_hdr->in_len, packet_hdr->len);
        }

        /* populate ethernet header */
        eth_hdr = ethernet_header();
        lt = eth_hdr->len_type;
        paylen = packet_hdr->in_len;

        if (lt == 0x0800) {
            // lt = show_ip();
            ip_hdr = ip_header();
            lt = ip_hdr->len;
        }
        else if (lt <= 1500)
            show_payload(lt);
        else
            assert(0);

        /* parse ip payload (TCP/UDP) */
        if (ip_hdr->protcl == 6) {          // TCP
            udp_hdr = NULL;
            tcp_hdr = tcp_header();
        }
        else if (ip_hdr->protcl == 17) {    // UDP
            tcp_hdr = NULL;
            udp_hdr = udp_header();
        }

        // flush payload
        if (tcp_hdr) {
            for (i = 0; i < ip_hdr->len - IP_HL(ip_hdr) * 4 - 20; i++)
                (void) getchar();
        }
        else {
            for (i = 0; i < ip_hdr->len - IP_HL(ip_hdr) * 4 - 8; i++)
                (void) getchar();
        }

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
        /* deallocate memory */
        free(packet_hdr);
        free(eth_hdr);
        free(ip_hdr);
        if(payload)
            free(payload);
        if (tcp_hdr)
            free(tcp_hdr);
        if (udp_hdr)
            free(udp_hdr);
        packet_hdr = NULL;
        eth_hdr = NULL;
        ip_hdr = NULL;
        tcp_hdr = NULL;
        udp_hdr = NULL;
        payload = NULL;
    }
    if (!raw_mode)
        free(global_hdr);
    return 0;
}

