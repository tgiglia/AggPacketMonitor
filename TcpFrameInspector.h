#pragma once
#include "BitMasking.h"
#include <iostream>
#include <in6addr.h>

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


struct ipv6_header
{
	unsigned int
		version : 4,
		traffic_class : 8,
		flow_label : 20;
	uint16_t length;
	uint8_t  next_header;
	uint8_t  hop_limit;
	struct in6_addr src;
	struct in6_addr dst;
};


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

class TcpFrameInspector {
protected:
	ip_header* ih;
	ipv6_header* i6h;
	tcp_header* tcpH;
	const unsigned char* pkt_data;
	u_short sport;
	u_short dport;
	u_short windowSize;
	u_short ipDataLen;
	u_short identification;
	u_int ip_len;
	u_int uiTcpHeaderSize;
	u_int uiPayloadLocation;
	int frameLength;
	unsigned int sequenceNum;
	unsigned int ackNum;
	char cpDestIp[64];
	unsigned char cpIPv6Dest[64];
	unsigned char cpIPv6Source[64];
	void showControlBits();
	void DisplayTotalLengthBits();
	void showFragmentBits();
	void showFragmentOffset();
	void showIPv6Header();
	void saveFrameToDisk(char* cpFile);
	bool deriveIPv6Addresses();
public:
	TcpFrameInspector(const unsigned char* pkt,int len);
	void inspectFrame();
	void inspectFrameNoDbg();
	void inspectFrameDbg();
	ip_header* rtIpHeader() { return ih; }
	tcp_header* rtTcpHeader() { return tcpH; }
	u_short rtSport() { return sport; }
	u_short rtDport() { return dport; }
	u_int rtIpLen() { return ip_len; }
	unsigned int rtSequenceNum() { return sequenceNum; }
	u_short rtWindowSize() { return windowSize; }
	unsigned int rtAckNum() { return ackNum; }
	u_int rtTcpHeaderSize() { return uiTcpHeaderSize; }
	u_short rtIpDataLen() { return ipDataLen; }
	u_int rtPayloadLocation() { return uiPayloadLocation; }
	u_short rtIdentification() { return identification; }
	char* rtDestIp() { return cpDestIp; }
	unsigned char* rtIPv6Source() { return cpIPv6Source; }
	unsigned char* rtIPv6Dest() { return cpIPv6Dest; }
	bool isMFBitSet();
	unsigned char getLeastSignificantNibble(unsigned char c) { return c & 0x0F; }
	unsigned char getMostSignificantNibble(unsigned char c) { unsigned char tmp = c & 0xF0; return tmp >> 4; }
	unsigned char translateNumberToChar(unsigned char c);
private:
	void IPv4Processor();
	void IPv6Processor();
	void writeAddressesToDisk(char* filepath);
	
};