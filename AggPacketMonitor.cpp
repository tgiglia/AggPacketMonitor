#include "pch.h"
#include <pcap.h>
#include <iostream>
#include "AnaylyzeWebsocketFrame.h"

int runNpcap();

using namespace System;
#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif


/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

//TCP Header
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	unsigned int sequence_number;
	unsigned int ack_number;
	u_short offset_res_control;//data offset=4bits,reserved=3bits,control flags=9bits
	u_short window_size;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void printBits(size_t const size, void const* const ptr);
int isStandard(unsigned char c);
void showPayloadData(u_char* ucp, int num);


int main(array<System::String ^> ^args)
{
	std::cout << "AggPacketMonitor started!" << std::endl;
	runNpcap();
	std::cout << "AggPacketMonitor terminating." << std::endl;
    return 0;
}


int runNpcap()
{
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	u_int netmask;
	char packet_filter[] = "ip and tcp and host 172.20.72.82 and dst port 5000";
	struct bpf_program fcode;
	unsigned short us = 5;
	
#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	//callAObject(us);
/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1;d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	printf("packet_filter = %s", packet_filter);

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, tcp_packet_handler, NULL);

	return 0;
}


void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	tcp_header* tcpH;
	u_int ip_len;
	u_int uiPayloadLocation;
	u_short sport, dport;
	u_short ipDataLen;
	u_short offset;
	u_short windowSize;
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;
	u_int uiTcpHeaderSize;
	u_char* ucpPayload;
	unsigned int sequenceNum;
	unsigned int ackNum;
	BYTE* pOffset;
	BYTE b = 0;
	int bStandard = 0;
	/*
	 * unused parameter
	 */
	(VOID)(param);
	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	/* retireve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcpH = (tcp_header*)((u_char*)ih + ip_len);

	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);
	ipDataLen = ntohs(ih->tlen);
	offset = tcpH->offset_res_control;
	leftOffSet = (u_char*)&tcpH->offset_res_control;
	windowSize = ntohs(tcpH->window_size);
	ucOffset = *leftOffSet;
	offsetShifted = ucOffset >> 4; //shift right to move the bits where care about to the begining.
	uiTcpHeaderSize = offsetShifted * 4;


	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d sequence: %u ack: %u ip len: %u window size: %u\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport, sequenceNum, ackNum, ipDataLen, windowSize);
	/*printf("\toffset: %d\t", offset);
	printBits(sizeof(offset), &offset);*/
	printf("\toffsetShifted %u\t", offsetShifted);
	printBits(sizeof(char), &offset);
	uiPayloadLocation = 14 + ip_len + uiTcpHeaderSize;
	printf("\tMAC: 14 IP Header is: %u TCP Header is: %u Total: %u\n", ip_len, uiTcpHeaderSize, (unsigned)uiPayloadLocation);
	ucpPayload = (u_char*)&pkt_data[uiPayloadLocation];
	if (ipDataLen > 256)
	{
		showPayloadData(ucpPayload, 5);
		AnalyzeWebSocketFrame* awf = new AnalyzeWebSocketFrame(ucpPayload, ipDataLen - uiPayloadLocation);
		awf->AnalyzeFrame();

		delete awf;
	}

	
}

void showPayloadData(u_char* ucp, int num)
{
	printf("\tPayload: ");
	for (int i = 0;i < num;i++)
	{
		printf("0x%x ", ucp[i]);
	}
	printf("\n");
}

//assumes little endian
void printBits(size_t const size, void const* const ptr)
{
	unsigned char* b = (unsigned char*)ptr;
	unsigned char byte;
	int i, j;

	for (i = size - 1;i >= 0;i--)
	{
		for (j = 7;j >= 0;j--)
		{
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}

int isStandard(unsigned char c)
{
	if (c < 240)
	{
		return 1;
	}
	return 0;
}
