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
    int         i,
                c = 0,      // packet count
                paylen,     // length of payload
                ch,
                pad;        // num of padded bytes (eth)
    pcap_h     *global_hdr; // packet headers
    pcap_rec_h *packet_hdr;
    eth_h      *eth_hdr;
    ip_h       *ip_hdr;
    tcp_h      *tcp_hdr;
    udp_h      *udp_hdr;
    char       *payload;    // payload
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
        eth_hdr = ethernet_header();
        printf("frame: ethernet 802.3\n");
        printf("  dst: %02x", eth_hdr->dst_eth[0]);
        for (i = 1; i < 6; i++)
            printf(":%02x", eth_hdr->dst_eth[i]);
        printf("\n  src: %02x", eth_hdr->src_eth[0]);
        for (i = 1; i < 6; i++)
            printf(":%02x", eth_hdr->src_eth[i]);
        printf("\n");

        if (eth_hdr->len_type == 0x0800) {     // ipv4
            ip_hdr = ip_header();
            printf("frame: ipv4\n");
            printf("  dst: %d", ip_hdr->dst_ip.oct[0]);
            for (i = 1; i < 4; i++)
                printf(".%d", ip_hdr->dst_ip.oct[i]);
            printf("\n  src: %d", ip_hdr->src_ip.oct[0]);
            for (i = 1; i < 4; i++)
                printf(".%d", ip_hdr->src_ip.oct[i]);
            printf("\n  ttl: %d\n", ip_hdr->ttl);
        }
        else if (eth_hdr->len_type <= 1500) {  // vlan payload
            show_payload(ip_hdr->len);
            paylen = eth_hdr->len_type;
        }
        else {
            fprintf(stderr, "undefined ethernet length/type: %04x\n",
                    eth_hdr->len_type);
            assert(0);
        }
        /* parse ip payload (TCP/UDP) */
        if (ip_hdr->protcl == 6) {          // TCP
            udp_hdr = NULL;
            tcp_hdr = tcp_header();
            paylen = ip_hdr->len \
                     - (IP_HL(ip_hdr) * WORD_LEN)\
                     - (T_HL(tcp_hdr) * WORD_LEN);
            // flush tcp options, if any
            for (i = 0; i < T_HL(tcp_hdr) - 5; i++)
                (void)get32();
        }
        else if (ip_hdr->protcl == 17) {    // UDP
            tcp_hdr = NULL;
            udp_hdr = udp_header();
            paylen = ip_hdr->len \
                     - (IP_HL(ip_hdr) * WORD_LEN) - 8;
        }
        payload = (char *) malloc(sizeof(char) * (paylen + 1));
        pad = packet_hdr->in_len - ETH_HLEN - ip_hdr->len;
        // flush payload
        for (i = 0; i < paylen; i++)
            payload[i] = getchar();
        payload[paylen] = '\0';
        /* check for DNS packet */
       if (!check_dns(udp_hdr, payload)) {
           (void) check_tcp(tcp_hdr);
           printf("\npayload length: %d\n%s\n", paylen, payload);
       }
        if (!raw_mode) {
            for (i = 0; i < pad; i++)
                printf("pad%d: %02x\n", i, getchar() & 0xff);
        }

        /* end loop */
        ch = getchar();
        if (ch == EOF)
            break;
        (void) ungetc(ch, stdin);
        printf("\n");
        /* deallocate memory */
        free(packet_hdr);
        free(eth_hdr);
        if(ip_hdr)
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

