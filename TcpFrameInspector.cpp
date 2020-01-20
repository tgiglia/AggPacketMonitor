#include "pch.h"
#include "TcpFrameInspector.h"

TcpFrameInspector::TcpFrameInspector(const unsigned char* pkt,int len) {
	pkt_data = pkt;
	ih = NULL;
	tcpH = NULL;
	frameLength = len;
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

void TcpFrameInspector::inspectFrameNoDbg() {
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
