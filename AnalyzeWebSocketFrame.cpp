#include "pch.h"
#include "AnaylyzeWebsocketFrame.h"
#include<iostream>
#include<stdio.h>
#include<string.h>
#include<bitset>

#include "BitMasking.h"
using namespace std;

AnalyzeWebSocketFrame::AnalyzeWebSocketFrame(unsigned char* f, int len) {
	cout << "AnalyzeWebSocketFrame::AnalyzeWebSocketFrame: len = " << len << " fLen=" << fLen << endl;
	//frame = new unsigned char(len+2);
	frame = f;
	fLen = len;
	cout << "AnalyzeWebSocketFrame::AnalyzeWebSocketFrame: After assignment len = " << len << " fLen=" << fLen << endl;
	
}
void AnalyzeWebSocketFrame::ShowMe() {
	printf("In Show, fLen = %d\n", fLen);


	cout << "In Show using cout\n";
	for (int i = 0;i < fLen;i++) {
		printf("idx: %d val:0x%x\n", i, frame[i]);
	}
}

void AnalyzeWebSocketFrame::AnalyzeFrame() {
	//First step is to look at the 2nd byte it tells you if the MASK Bit is set and if the payload is contained
	//in the that byte < 126, in the next two bytes = 126 or the next 4 bytes = 127
	BYTE  byteTwo = frame[1];
	//Is the MASK Bit Set?
	CBitMasking mask(byteTwo);
	std::cout << "\nAnalyzeWebSocketFrame::AnalyzeFrame: Initial value is:";
	mask.Display();
	if (mask.CheckBit(CBitMasking::Bit8)) {
		std::cout << "\nEighth bit is on";
		isMaskSet = true;
	}
	else {
		std::cout << "\nEighth bit is off";
		isMaskSet = false;
	}
	//Mask off bit 8 and check the remaining value
	mask.ClearBit(CBitMasking::Bit8);
	std::cout << "\nAfter clearing bit8\n";
	mask.Display();
	BYTE cleared8 = mask.rtMask();
	if (cleared8 < 126) {
		int iMaskStart = 2;
		int iPayloadStart = 6;
		printf("\nThe payload size is less than 126: %d\n", cleared8);
		//the next four bytes are the mask.
		
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		const char *cpPayload = DecodePayload(ucpMask, ucpPayload, iPayloadSize);
		printf("Payload: %s\n", cpPayload);

	}
	else if (cleared8 == 126) {
		int iMaskStart = 4;
		int iPayloadStart = 8;
		std::cout << "\nThe payload size is in the next 2 bytes.";
		//Move the next two bytes into a 16 bit unsigned integer
		int payloadSize = frame[3] | frame[2] << 8;
		printf("frame[2] = 0X%x frame[3] = 0X%x\n", frame[2], frame[3]);
		cout << "payloadSize = " << payloadSize << endl;
		//cout << std::bitset<16>(payloadSize);
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		const char* cpPayload = DecodePayload(ucpMask, ucpPayload, payloadSize);
		printf("Payload: %s\n", cpPayload);
	}
	else if (cleared8 == 127) {
		std::cout << "\nThe payload size is in the next 8 bytes.";
		int iMaskStart = 10;
		int iPayloadStart = 14;
		//You get the payload size from the 2,3,4,5,6,7,8,9
		unsigned char ucpPayloadSize[8] = { frame[3], frame[2],frame[5],frame[4],frame[7],frame[6],frame[9],frame[8] };
		unsigned long long payloadSize;
		memcpy(&payloadSize, ucpPayloadSize, sizeof(unsigned long long));
		cout << "payloadSize = " << payloadSize << endl;
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		const char* cpPayload = DecodePayload(ucpMask, ucpPayload, payloadSize);
		//printf("Payload: %s\n", cpPayload);

	}
}

const char *AnalyzeWebSocketFrame::DecodePayload(unsigned char* ucpMask, unsigned char* ucpPayload, int iLen) {
	string str;
	for (int i = 0;i < iLen;i++) {
		unsigned char key = ucpMask[i % 4];
		unsigned char theChar = ucpPayload[i] ^ key;
		//printf("%d Key: 0x%x Masked: 0x%x Unmasked: %c\n", i,key, ucpPayload[i], theChar);
		str.push_back(theChar);
	}
	cout << "AnalyzeWebSocketFrame::DecodePayload: unmasked payload: " << str << endl;
	cpPayload = new char(strlen(str.c_str()));
	const char* cp = str.c_str();
	strcpy(cpPayload, cp);
	return cpPayload;
}