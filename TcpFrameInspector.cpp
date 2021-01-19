#include "pch.h"
#include "TcpFrameInspector.h"
#include <iostream>
#include <fstream>



TcpFrameInspector::TcpFrameInspector(const unsigned char* pkt,int len) {
	pkt_data = pkt;
	ih = NULL;
	tcpH = NULL;
	frameLength = len;
	memset(cpIPv6Dest, 0, sizeof(cpIPv6Dest));
	memset(cpIPv6Source, 0, sizeof(cpIPv6Source));
}

void TcpFrameInspector::inspectFrame() {
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	/* retrieve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcpH = (tcp_header*)((u_char*)ih + ip_len);

	identification = ntohs(ih->identification);
	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	windowSize = ntohs(tcpH->window_size);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);
	
	leftOffSet = (u_char*)&tcpH->offset_res_control;
	ucOffset = *leftOffSet;
	offsetShifted = ucOffset >> 4; //shift right to move the bits we care about to the begining.
	uiTcpHeaderSize = offsetShifted * 4;
	ipDataLen = ntohs(ih->tlen);
	if (ipDataLen > frameLength) {
		ipDataLen = frameLength;
	}
	
	uiPayloadLocation = 14 + ip_len + uiTcpHeaderSize;
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d sequence: %u ack: %u Pos TCP Header: %u window size: %u\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport, sequenceNum, ackNum, ip_len, windowSize);
	sprintf(cpDestIp, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	printf("identification: %u\n", identification);
	showFragmentBits();
	showFragmentOffset();
	printf("uiTcpHeaderSize is: %u Total Length (Eth Header+ TCP Header + Data): %u Payload Location: %u\n", 
		uiTcpHeaderSize, ipDataLen + 14, uiPayloadLocation);
	DisplayTotalLengthBits();
	showControlBits();
}

void TcpFrameInspector::inspectFrameDbg() {
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	u_char verTmp = ih->ver_ihl;
	u_char cVersion = verTmp >> 4;
	//printf("IP Version: %d\n\n", cVersion);
	if (cVersion == 4) {
		IPv4Processor();
		printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d sequence: %u ack: %u Pos TCP Header: %u window size: %u\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			sport,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4,
			dport, sequenceNum, ackNum, ip_len, windowSize);
	}
	else {
		i6h = (ipv6_header *)(pkt_data +
			14); //length of ethernet header
		IPv6Processor();
		std::cout << "\tLength: " << ip_len << std::endl;
		std::cout << "\tSource Address: " << cpIPv6Source << std::endl;
		std::cout << "\tDestination Address: " << cpIPv6Dest << std::endl;
		puts("");
	}	
	
}

void TcpFrameInspector::IPv6Processor() {
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;

	memset(cpIPv6Dest, 0, sizeof(cpIPv6Dest));
	memset(cpIPv6Source, 0, sizeof(cpIPv6Source));

	//printf("\tThis is a IPv6 packet!\n");
	//showIPv6Header();
	tcpH = (tcp_header*)(pkt_data + 54);
	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	
	windowSize = ntohs(tcpH->window_size);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);

	leftOffSet = (u_char*)&tcpH->offset_res_control;
	ucOffset = *leftOffSet;
	offsetShifted = ucOffset >> 4; //shift right to move the bits we care about to the begining.
	uiTcpHeaderSize = offsetShifted * 4;

	uiPayloadLocation = 54 + uiTcpHeaderSize;
	
	deriveIPv6Addresses();
	/*printf("TcpFrameInspector::IPv6Processor: sport: %d  dport: %d windowSize: %u sequenceNum: %u ackNum: %u TcpHeaderSize: %u PayloadLocation: %u\n",
		sport,dport,windowSize,sequenceNum,ackNum,uiTcpHeaderSize,uiPayloadLocation);*/
	//printf("TcpFrameInspector::IPv6Processor: cpIPv6Source: %s\n", cpIPv6Source);
	//printf("TcpFrameInspector::IPv6Processor: cpIPv6Des: %s\n", cpIPv6Dest);
	//saveFrameToDisk("IPv6.txt");
	
}

bool TcpFrameInspector::deriveIPv6Addresses() {
	memset(cpIPv6Source, 0, sizeof(cpIPv6Source));
	memset(cpIPv6Dest, 0, sizeof(cpIPv6Dest));
	int iTotal = 0;
	int iGroupCount = 0;

	for (int i = 22;i < 38;i++) {
		unsigned char tmp = pkt_data[i];
		unsigned char upperNibble = getMostSignificantNibble(tmp);
		unsigned char lowerNibble = getLeastSignificantNibble(tmp);
		unsigned char tranUpper = translateNumberToChar(upperNibble);
		unsigned char tranLower = translateNumberToChar(lowerNibble);
		cpIPv6Source[iTotal] = tranUpper;
		iTotal++;
		iGroupCount++;
		cpIPv6Source[iTotal] = tranLower;
		iTotal++;
		iGroupCount++;
		if (iGroupCount >= 3) {
			cpIPv6Source[iTotal] = ':';
			iTotal++;
			iGroupCount = 0;
		}
	}
	cpIPv6Source[iTotal - 1] = 0;
	iTotal = 0;
	iGroupCount = 0;

	for (int i = 38;i < 54;i++) {
		unsigned char tmp = pkt_data[i];
		unsigned char upperNibble = getMostSignificantNibble(tmp);
		unsigned char lowerNibble = getLeastSignificantNibble(tmp);
		unsigned char tranUpper = translateNumberToChar(upperNibble);
		unsigned char tranLower = translateNumberToChar(lowerNibble);
		cpIPv6Dest[iTotal] = tranUpper;
		iTotal++;
		iGroupCount++;
		cpIPv6Dest[iTotal] = tranLower;
		iTotal++;
		iGroupCount++;
		if (iGroupCount >= 3) {
			cpIPv6Dest[iTotal] = ':';
			iTotal++;
			iGroupCount = 0;
		}
	}
	cpIPv6Dest[iTotal - 1] = 0;
	return true;
}

void TcpFrameInspector::saveFrameToDisk(char* cpFile) {
	
	std::ofstream outfile;
	char cpTemp[256];

	outfile.open(cpFile, std::ios_base::app); // append instead of overwrite
	int i = 0;
	int iSize = 40;
	for (i = 0;i < 40;i++) {
		memset(cpTemp, sizeof(cpTemp), 0);
		if (i < iSize - 1) {
			sprintf_s(cpTemp, sizeof(cpTemp), "0x%x,", i6h[i]);
		}
		else {
			sprintf_s(cpTemp, sizeof(cpTemp), "0x%x\n", i6h[i]);
		}
		outfile << cpTemp;
	}
	outfile.close();
}

void TcpFrameInspector::showIPv6Header() {
	printf("\tThe frame length is: %d\n", frameLength);
	printf("\tversion: %d\n", i6h->version);
	printf("\tnext header: %d\n", i6h->next_header);
	printf("\tlength: %d\n", ntohs(i6h->length));
}


void TcpFrameInspector::inspectFrameNoDbg() {
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	u_char verTmp = ih->ver_ihl;
	u_char cVersion = verTmp >> 4;
	if (cVersion == 4) {
		IPv4Processor();
	}
	else {
		i6h = (ipv6_header*)(pkt_data +
			14); //length of ethernet header
		IPv6Processor();
		//showIPv6Header();
	}
	
}


void TcpFrameInspector::IPv4Processor() {
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	/* retrieve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcpH = (tcp_header*)((u_char*)ih + ip_len);

	identification = ntohs(ih->identification);
	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	windowSize = ntohs(tcpH->window_size);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);

	leftOffSet = (u_char*)&tcpH->offset_res_control;
	ucOffset = *leftOffSet;
	offsetShifted = ucOffset >> 4; //shift right to move the bits we care about to the begining.
	uiTcpHeaderSize = offsetShifted * 4;
	ipDataLen = ntohs(ih->tlen);

	sprintf(cpDestIp, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
	uiPayloadLocation = 14 + ip_len + uiTcpHeaderSize;
}



void TcpFrameInspector::DisplayTotalLengthBits() {
	u_char* pTotalLen = (u_char*)&ih->tlen;
	BYTE b1 = pTotalLen[0];
	BYTE b2 = pTotalLen[1];
	CBitMasking mask(b1);
	CBitMasking mask2(b2);
	std::cout << "TotalLen 1: ";
	mask.Display(); puts("");
	std::cout << "TotalLen 2: ";
	mask2.Display();puts("");

}

void TcpFrameInspector::showControlBits() {
	u_char* pOffSet = (u_char*)&tcpH->offset_res_control;
	BYTE b = pOffSet[0];
	BYTE b2 = pOffSet[1];

	CBitMasking mask(b);
	CBitMasking mask2(b2);
	std::cout << "Offset 0: ";
	mask.Display();puts("");
	std::cout << "Offset 1: ";
	mask2.Display();puts("");
	std::cout << "Control Bits: ";
	if (mask.CheckBit(CBitMasking::Bit1)) {
		std::cout << " Concealment Protection, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit8)) {
		std::cout << "Congestion Window Reduced, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit7) && mask2.CheckBit(CBitMasking::Bit2)) {
		std::cout << "TCP peer is ECN capable, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit6)) {
		std::cout << "Urgent pointer field is significant, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit5)) {
		std::cout << "Ack field is significant, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit4)) {
		std::cout << "Push function, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit3)) {
		std::cout << "Reset the connection, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit2)) {
		std::cout << "Synchronize sequence numbers, ";
	}
	if (mask2.CheckBit(CBitMasking::Bit1)) {
		std::cout << "Last packet from sender, ";
	}
	std::cout << std::endl;
}

void TcpFrameInspector::showFragmentBits() {
	u_char* pFragFlags = (u_char*)&ih->flags_fo;
	BYTE b = pFragFlags[0];
	CBitMasking mask(b);
	std::cout << "Fragment Bits: ";
	mask.Display(); std::cout << " ";
	if (mask.CheckBit(CBitMasking::Bit8)) {
		std::cout << "Reserved bit is set - should be zero, ";
	}
	if (mask.CheckBit(CBitMasking::Bit7)) {
		std::cout << "Don't Fragment, ";
	}
	if (mask.CheckBit(CBitMasking::Bit6)) {
		std::cout << "MF bit set";
	}
	else {
		std::cout << "MF bit NOT set.";
	}
	std::cout << std::endl;
}

bool TcpFrameInspector::isMFBitSet() {
	u_char* pFragFlags = (u_char*)&ih->flags_fo;
	BYTE b = pFragFlags[0];
	CBitMasking mask(b);
	return mask.CheckBit(CBitMasking::Bit6);
}

void TcpFrameInspector::showFragmentOffset() {
	u_char * pFragFlags = (u_char*)&ih->flags_fo;
	BYTE b = pFragFlags[0];
	BYTE b2 = pFragFlags[1];
	CBitMasking mask(b);
	CBitMasking mask2(b);
	mask.ClearBit(CBitMasking::Bit8);mask.ClearBit(CBitMasking::Bit7);mask.ClearBit(CBitMasking::Bit6);
	std::cout << "FragmentOffSet: ";
	mask.Display(); std::cout << ":"; mask2.Display();
	std::cout << std::endl;

}


void TcpFrameInspector::writeAddressesToDisk(char* filepath) {
	std::ofstream* outf;

}

unsigned char TcpFrameInspector::translateNumberToChar(unsigned char c) {
	switch (c) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 10: return 'A';
	case 11: return 'B';
	case 12: return 'C';
	case 13: return 'D';
	case 14: return 'E';
	case 15: return 'F';

	}
	return 'Z';
}

