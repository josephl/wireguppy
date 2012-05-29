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

    // packet headers
    pcap_h *global_hdr;
    pcap_rec_h *packet_hdr;
    eth_h  *eth_hdr;
    ip_h   *ip_hdr;
    tcp_h  *tcp_hdr;
    udp_h  *udp_hdr;

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
        int lt, ch;
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            packet_hdr = packet_header();
            printf("length: %d (%d)\n", packet_hdr->in_len, packet_hdr->len);
        }
        // printf("src: ");
        // print_ether();
        // printf("\n");
        // printf("dst: ");
        // print_ether();
        // printf("\n");
        // lt = decode_length_type();
        // if (lt == 0x0800)
        //     lt = show_ip();
        // else if (lt <= 1500)
        //     show_payload(lt);
        // else
        //     assert(0);
        /* populate ethernet header */
        eth_hdr = ethernet_header();
        lt = eth_hdr->len_type;

        if (lt == 0x0800)
            lt = show_ip();
        else if (lt <= 1500)
            show_payload(lt);
        else
            assert(0);

        assert(packet_hdr->in_len >= lt - 14);
        if (!raw_mode) {
            packet_hdr->in_len -= 14; /* ethernet header */
            packet_hdr->in_len -= lt; /* IP packet */
            for (i = 0; i < packet_hdr->in_len; i++)
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

