# uncookedPCAP
uncook a linux pcap trace - remove linux cooked capture header (SLL) and replace with a fake ethernet header.

Source MAC will be 01:01:01:01:01:01 and Destination MAC will be 02:02:02:02:02:02

Usage:

uncookedPCAP infile.pcap outfile.pcap
