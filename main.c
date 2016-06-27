/* 
 * File:   main.c
 * Author: jaybeepee
 *
 * Created on 27 June 2016, 12:00 PM
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

/*
 * 
 */
int main(int argc, char** argv)
{
	unsigned char rawheader[14] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x81, 0x00};
	pcap_t* handle = NULL;
	pcap_t* out_handle = NULL;
	pcap_dumper_t* dumper = NULL;
	unsigned char* data;
	unsigned char* new_data;
	unsigned int new_data_len;
	struct pcap_pkthdr pkt;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned int count = 0;
	char *infile, *outfile;

	if (argc < 3) {
		printf("Usage: uncookedPCAP ifile ofile\n");
		goto done;
	}
	infile = argv[1];
	outfile = argv[2];
	handle = pcap_open_offline(infile, errbuf);
	if (!handle) {
		printf("unable to open file: '%s'\n", infile);
		goto done;
	}
	
	if (DLT_LINUX_SLL != pcap_datalink(handle)) {
		printf("not an SLL linktype\n");
		goto done;
	}
	
	out_handle = pcap_open_dead(DLT_EN10MB, 65535);
	if (!out_handle) {
		printf("unable to open output file: '%s'\n", outfile);
		goto done;
	}
	dumper = pcap_dump_open(out_handle, outfile);
	
	while ((data=(unsigned char*)pcap_next(handle, &pkt)) != NULL) {
		new_data = data;
		new_data_len = pkt.len - 2;
		int sll_type_hb = data[14];
		int sll_type_lb = data[15];
		for (int i=2; i < 14; i++) {
			new_data[i] = rawheader[i-2];
		}
		new_data[14] = sll_type_hb;
		new_data[15] = sll_type_lb;
		pkt.len -= 2;
		pcap_dump((unsigned char*)dumper, &pkt, &new_data[2]);
		count++;
	}
	
	done:
	
	printf("%u packets processed\n", count);
	
	if (handle)
		pcap_close(handle);
	if (out_handle)
		pcap_close(out_handle);

	return(EXIT_SUCCESS);
}

