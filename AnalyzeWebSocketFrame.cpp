#include "pch.h"
#include "AnaylyzeWebsocketFrame.h"
#include<iostream>
#include<stdio.h>
#include<string.h>
#include<bitset>

#include "BitMasking.h"
#include "WSFirstByteDecoder.h"
using namespace std;

AnalyzeWebSocketFrame::AnalyzeWebSocketFrame(unsigned char* f, int len) {	
	frame = f;
	fLen = len;
	iFrameType = 0;
	btMaskStart = 0;
	btPayloadStart = 0;
	ucpMaskStart = NULL;
	ucpPayloadStart = NULL;
	ullPayloadSize = 0;
}
void AnalyzeWebSocketFrame::ShowMe() {
	printf("In Show, fLen = %d\n", fLen);


	cout << "In Show using cout\n";
	for (int i = 0;i < fLen;i++) {
		printf("idx: %d val:0x%x\t%c\n", i, frame[i],frame[i]);
	}
}


void AnalyzeWebSocketFrame::checkFinBit() {
	BYTE b = (BYTE)frame[0];

	WSFirstByteDecoder wsfbd(b);
	if (wsfbd.finalFragment()) {
		std::cout << "This is the final fragment in the message." << std::endl;
	}
	else {
		std::cout << "This is not the final fragment in the message." << std::endl;
	}

}

void AnalyzeWebSocketFrame::checkOpCode() {
	BYTE b = (BYTE)frame[0];
	std::string s;
	WSFirstByteDecoder wsfbd(b);
	wsfbd.getOpCode(s);
	cout <<"This is a: "<< s << endl;
}

void AnalyzeWebSocketFrame::checkMask() {
	BYTE  byteTwo = frame[1];
	CBitMasking mask(byteTwo);
	if (mask.CheckBit(CBitMasking::Bit8)) {
		std::cout << "Mask bit is SET." << std::endl;
		isMaskSet = true;
	}
	else {
		std::cout << "Mask bit is NOT SET." << std::endl;
		isMaskSet = false;
	}
}

void AnalyzeWebSocketFrame::checkPayloadLength() {
	BYTE  byteTwo = frame[1];
	CBitMasking mask(byteTwo);
	//Mask off bit 8 and check the remaining value
	mask.ClearBit(CBitMasking::Bit8);
	BYTE cleared8 = mask.rtMask();
	if (cleared8 < 126) {
		printf("Payload Size is: %d\n", cleared8);
		ullPayloadSize = cleared8;
		iFrameType = 1;
	}
	else if (cleared8 == 126) {
		//Move the next two bytes into a 16 bit unsigned integer
		int iPayloadSize = frame[3] | frame[2] << 8;
		printf("Payload Size: %d\n", iPayloadSize);
		ullPayloadSize = iPayloadSize;
		iFrameType = 2;
	}
	else if(cleared8 == 127) {
		unsigned char ucpPayloadSize[8] = { frame[3], frame[2],frame[5],frame[4],frame[7],frame[6],frame[9],frame[8] };		
		memcpy(&ullPayloadSize, ucpPayloadSize, sizeof(unsigned long long));
		std::cout << "Payload Size: " << ullPayloadSize << std::endl;
		iFrameType = 3;
	}
}


void AnalyzeWebSocketFrame::checkMaskingKeys() {
	if (!isMaskSet) {
		std::cout << "Mask bit is not set for this frame." << std::endl;
		return;
	}
	//Set the masking key start location based on the payload frames
	if (iFrameType == 0) {//checkPayloadLength() was not called so call it now
		checkPayloadLength();
	}
	switch (iFrameType) {
	case 1:
		btMaskStart = 2;
		btPayloadStart = 6;
		break;
	case 2:
		btMaskStart = 4;
		btPayloadStart = 8;
		break;
	case 3:
		btMaskStart = 10;
		btPayloadStart = 14;
		break;
	default: std::cout << "ERROR could not determine Mask and Payload start indexs." << std::endl;
		return;
	}
	ucpMaskStart = &frame[btMaskStart];
	ucpPayloadStart = &frame[btPayloadStart];
	showMaskingKeys();
}

void AnalyzeWebSocketFrame::showMaskingKeys() {
	printf("MASKING KEYS: ");
	for (int i = 0;i < 4;i++) {
		printf("0x%x ", ucpMaskStart[i]);
	}
	puts("");
}

void AnalyzeWebSocketFrame::showDecodedPayload() {
	std::cout << "THE PAYLOAD: " << std::endl;
	for (int i = 0;i < ullPayloadSize;i++) {
		unsigned char key = ucpMaskStart[i % 4];
		unsigned char theChar = ucpPayloadStart[i] ^ key;
		printf("%d Key: 0x%x Masked: 0x%x Unmasked: %c\n", i,key, ucpPayloadStart[i], theChar);
	}
	std::cout << std::endl;
}

void AnalyzeWebSocketFrame::AnalyzeFrame(std::string *strp)
{
	//First step is to look at the 2nd byte it tells you if the MASK Bit is set and if the payload is contained
	//in the that byte < 126, in the next two bytes = 126 or the next 4 bytes = 127
	BYTE  byteTwo = frame[1];
	//Is the MASK Bit Set?
	CBitMasking mask(byteTwo);
	//std::cout << "\nAnalyzeWebSocketFrame::AnalyzeFrame: Initial value is:";
	//mask.Display();
	if (mask.CheckBit(CBitMasking::Bit8)) {
		//std::cout << "\nEighth bit is on";
		isMaskSet = true;
	}
	else {
		//std::cout << "\nEighth bit is off";
		isMaskSet = false;
	}
	//Mask off bit 8 and check the remaining value
	mask.ClearBit(CBitMasking::Bit8);
	//std::cout << "\nAfter clearing bit8\n";
	//mask.Display();
	BYTE cleared8 = mask.rtMask();
	if (cleared8 < 126) {
		int iMaskStart = 2;
		int iPayloadStart = 6;
		//printf("\nThe payload size is less than 126: %d\n", cleared8);
		//the next four bytes are the mask.

		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		//printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		DecodePayload(ucpMask, ucpPayload, iPayloadSize,strp);

	}
	else if (cleared8 == 126) {
		int iMaskStart = 4;
		int iPayloadStart = 8;
		//std::cout << "\nThe payload size is in the next 2 bytes.";
		//Move the next two bytes into a 16 bit unsigned integer
		int payloadSize = frame[3] | frame[2] << 8;
		//printf("frame[2] = 0X%x frame[3] = 0X%x\n", frame[2], frame[3]);
		//cout << "payloadSize = " << payloadSize << endl;
		//cout << std::bitset<16>(payloadSize);
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		//printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		DecodePayload(ucpMask, ucpPayload, payloadSize,strp);
		
	}
	else if (cleared8 == 127) {
		//std::cout << "\nThe payload size is in the next 8 bytes.";
		int iMaskStart = 10;
		int iPayloadStart = 14;
		//You get the payload size from the 2,3,4,5,6,7,8,9
		unsigned char ucpPayloadSize[8] = { frame[3], frame[2],frame[5],frame[4],frame[7],frame[6],frame[9],frame[8] };
		unsigned long long payloadSize;
		memcpy(&payloadSize, ucpPayloadSize, sizeof(unsigned long long));
		//cout << "payloadSize = " << payloadSize << endl;
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		DecodePayload(ucpMask, ucpPayload, payloadSize,strp);
		

	}

}
void AnalyzeWebSocketFrame::AnalyzeFrame() {
	//First step is to look at the 2nd byte it tells you if the MASK Bit is set and if the payload is contained
	//in the that byte < 126, in the next two bytes = 126 or the next 4 bytes = 127
	BYTE  byteTwo = frame[1];
	//Is the MASK Bit Set?
	CBitMasking mask(byteTwo);
	//std::cout << "\nAnalyzeWebSocketFrame::AnalyzeFrame: Initial value is:";
	mask.Display();
	if (mask.CheckBit(CBitMasking::Bit8)) {
		//std::cout << "\nEighth bit is on";
		isMaskSet = true;
	}
	else {
		//std::cout << "\nEighth bit is off";
		isMaskSet = false;
	}
	//Mask off bit 8 and check the remaining value
	mask.ClearBit(CBitMasking::Bit8);
	//std::cout << "\nAfter clearing bit8\n";
	mask.Display();
	BYTE cleared8 = mask.rtMask();
	if (cleared8 < 126) {
		int iMaskStart = 2;
		int iPayloadStart = 6;
		//printf("\nThe payload size is less than 126: %d\n", cleared8);
		//the next four bytes are the mask.
		
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		//printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		const char *cpPayload = DecodePayload(ucpMask, ucpPayload, iPayloadSize);
		//printf("Payload: %s\n", cpPayload);

	}
	else if (cleared8 == 126) {
		int iMaskStart = 4;
		int iPayloadStart = 8;
		//std::cout << "\nThe payload size is in the next 2 bytes.";
		//Move the next two bytes into a 16 bit unsigned integer
		int payloadSize = frame[3] | frame[2] << 8;
		//printf("frame[2] = 0X%x frame[3] = 0X%x\n", frame[2], frame[3]);
		//cout << "payloadSize = " << payloadSize << endl;
		//cout << std::bitset<16>(payloadSize);
		unsigned char* ucpMask = &frame[iMaskStart];
		unsigned char* ucpPayload = &frame[iPayloadStart];
		int iPayloadSize = fLen - iPayloadStart;
		//printf("Mask[0] = 0x%x Payload[0] = 0x%x iPayloadSize = %d\n", ucpMask[0], ucpPayload[0], iPayloadSize);
		const char* cpPayload = DecodePayload(ucpMask, ucpPayload, payloadSize);
		//printf("Payload: %s\n", cpPayload);
	}
	else if (cleared8 == 127) {
		//std::cout << "\nThe payload size is in the next 8 bytes.";
		int iMaskStart = 10;
		int iPayloadStart = 14;
		//You get the payload size from the 2,3,4,5,6,7,8,9
		unsigned char ucpPayloadSize[8] = { frame[3], frame[2],frame[5],frame[4],frame[7],frame[6],frame[9],frame[8] };
		unsigned long long payloadSize;
		memcpy(&payloadSize, ucpPayloadSize, sizeof(unsigned long long));
		//cout << "payloadSize = " << payloadSize << endl;
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
	
	return NULL;
}


void AnalyzeWebSocketFrame::DecodePayload(unsigned char* ucpMask, unsigned char* ucpPayload, int iLen, std::string *strp)
{
	for (int i = 0;i < iLen;i++) {
		unsigned char key = ucpMask[i % 4];
		unsigned char theChar = ucpPayload[i] ^ key;
		//printf("%d Key: 0x%x Masked: 0x%x Unmasked: %c\n", i,key, ucpPayload[i], theChar);
		strp->push_back(theChar);
	}
	//cout << "AnalyzeWebSocketFrame::DecodePayload: unmasked payload: " << *strp << endl;
}
