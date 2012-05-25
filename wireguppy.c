/*
 * Copyright © 2012 Bart Massey
 * [This program is licensed under the "MIT License"]
 * Please see the file COPYING in the source
 * distribution of this software for license terms.
 */

/*
 * Copyright (c) 2012 Joseph Lee
 * Also licensed under the "MIT License"
 * CS 494 - Internetworking Protocols
 */

/* Decode captured packet stream */

#include <assert.h>
#include <stdio.h>
#include <string.h>

// print IP address
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
int datalink; // datalink type, as per global header


// Parse and interpret PCap global header
// return: data link type
int global_header();


int main(int argc, char **argv) {

    int i;

    // Require 0 or 1 arg: "-r"
    if (argc == 2) {
        assert(!strcmp(argv[1], "-r"));
        raw_mode = 1; // raw-mode enabled
    } else {
        assert(argc == 1); // non-raw mode
    }

    if (!raw_mode) {
        /* XXX Should check link type and
           record snapshot length. */
        /*for (i = 0; i < 6; i++)
            printf("h%d: %08x\n", i, get32());
        printf("\n");*/
        datalink = global_header();
        if (datalink == 1) 
            printf("Ethernet Protocol\n\n");
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
        print_ether();  // print IPv6 addr
        printf("\n");
        printf("dst: ");
        print_ether();  // print IPv6 addr
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


int global_header() {

    int temp;

    // h0 - magic number
    temp = get32();
    assert(temp == 0xd4c3b2a1); // pcap magic number

    // h1 - PCap format version (2.4)
    printf("PCap Format Version %d.", get16() >> 8);
    printf("%d\n", get16() >> 8);

    // h2 - GMT to local correction
    (void) get32();

    // h3 - timestamp sig figs
    (void) get32();

    // h4 - snaplen
    (void) get32();

    // h5 - datalink type (1: ethernet)
    return get32() >> 24;

}
