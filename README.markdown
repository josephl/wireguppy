# Wireguppy
Copyright © 2010 Bart Massey

Wireguppy is a ridiculously incomplete command-line PCAP
trace inspector in the style of WireShark
(http://wireshark.org).

Right now Wireguppy works only on Ethernet PCAP packet trace
files in little-endian format (or raw concatenated traces
with the "-r" option), prints very little useful
information, and crashes if it sees something it doesn't
understand.

Why is it up at all, then? Because I am asking my students to
improve it as a homework assignment in the Networking course
I am teaching.

The file packets.pcap in this directory contains a PCAP
packet trace to play with.

Wireguppy is released under the MIT license. Please see the
file COPYING in this distribution for license information.
