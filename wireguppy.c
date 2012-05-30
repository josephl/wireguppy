/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */

/* Decode captured packet stream
 * LibPCAP Version 2.4 capture format
 *
 * Handles frame stack:
 * Ethernet 802.3
 * IPv4 | IPv6 | IPv4 Tunneling | TODO: ARP
 * TCP | UDP
 */

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
    int         c = 0,      // packet count
                ch;
    pcap_h     *global_hdr; // capture header
    pcap_rec_h *packet_hdr; // packet header

    /* check raw mode flag */
    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1;
    }
    else
        assert(argc == 1);

    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        /* Get Global PCAP header */
        global_hdr = global_header();
        printf("PCAP Version %d.%d\nMax length: %d\n\n",
                global_hdr->ver_maj,
                global_hdr->ver_min,
                global_hdr->snaplen);
    }
    while (1) {
        if (!raw_mode) {
            /* XXX Should use length information
               in decoding below. */
            packet_hdr = packet_header();
            printf("Packet %d | length: %d\n", ++c, packet_hdr->len);
        }

        /* populate ethernet header */
        ethernet_header(packet_hdr->in_len);
        /* end loop */
        ch = getchar();
        if (ch == EOF)
            break;
        (void) ungetc(ch, stdin);
        printf("\n");
        free(packet_hdr);
    }
    if (!raw_mode)
        free(global_hdr);
    return 0;
}

