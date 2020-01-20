#include "pch.h"
#include "AnalyzeWebSocketFrameVector.h"
#include <fstream>

using namespace std;
extern std::ofstream* errorf;

void AnalyzeWebsocketFrameVector::AnalyzeFrame(PCapFrameVector& pcfv, std::string* strp, u_int uiPayloadLocation) {
	int iMaskStart = 0;
	int iDataStart = 0;
	u_int WSPayloadLength = 0;
	BYTE  byteTwo;
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	try {
		byteTwo = pv->at(uiPayloadLocation + 1);
	}
	catch (std::out_of_range) {
		cout << "AnalyzeWebsocketFrameVector::AnalyzeFrame: out of range error. pv size is: " << pv->size() << " trying to get location: " << uiPayloadLocation + 1 << std::endl;
		return;
	}
	//Is the MASK Bit Set?
	CBitMasking mask(byteTwo);
	if (mask.CheckBit(CBitMasking::Bit8)) {
		isMaskSet = true;
	}
	else {
		isMaskSet = false;
	}
	//Mask off bit 8 and check the remaining value
	mask.ClearBit(CBitMasking::Bit8);
	//std::cout << "\nAfter clearing bit8\n";
	//mask.Display();
	BYTE cleared8 = mask.rtMask();
	u_int uiWSPayloadSize = pv->size() - uiPayloadLocation;//THIS IS THE SIZE OF THE DATA AFTER THE START OF THE PAYLOAD
	if (cleared8 < 126) {
		iMaskStart = 2 + uiPayloadLocation;
		iDataStart = 6 + uiPayloadLocation;
		if (pv->size() <= (uiPayloadLocation + iDataStart)) {
			return;
		}
		//The payload size is in byteTwo.
		WSPayloadLength = (u_int)byteTwo;
	}
	else if (cleared8 == 126) {
		iMaskStart = 4 + uiPayloadLocation;
		iDataStart = 8 + uiPayloadLocation;
		if (pv->size() <= (uiPayloadLocation + iDataStart)) {
			return;
		}
		unsigned char frame2 = pv->at(uiPayloadLocation + 2);
		unsigned char frame3 = pv->at(uiPayloadLocation + 3);
		WSPayloadLength = frame3 | frame2 << 8;
	}
	else if (cleared8 == 127) {
		iMaskStart = 10 + uiPayloadLocation;
		iDataStart = 14 + uiPayloadLocation;
		if (pv->size() <= (uiPayloadLocation + iDataStart)) {
			return;
		}
		
		unsigned char frame2 = pv->at(uiPayloadLocation + 2);
		unsigned char frame3 = pv->at(uiPayloadLocation + 3);
		unsigned char frame4 = pv->at(uiPayloadLocation + 4);
		unsigned char frame5 = pv->at(uiPayloadLocation + 5);
		unsigned char frame6 = pv->at(uiPayloadLocation + 6);
		unsigned char frame7 = pv->at(uiPayloadLocation + 7);
		unsigned char frame8 = pv->at(uiPayloadLocation + 8);
		unsigned char frame9 = pv->at(uiPayloadLocation + 9);
		unsigned char ucpPayloadSize[8] = { frame3, frame2,frame5,frame4,frame7,frame6,frame9,frame8 };
		unsigned long long payloadSize;
		memcpy(&payloadSize, ucpPayloadSize, sizeof(unsigned long long));

	}
	DecodePayload(pcfv, strp, uiPayloadLocation, iMaskStart, iDataStart, WSPayloadLength);

}

void AnalyzeWebsocketFrameVector::DecodePayload(PCapFrameVector& pcfv, std::string* strp, u_int uiPayloadLocation,
	int iMaskStart, int iDataStart, unsigned long long WSPayloadLength) {
	int iEndData = 0;
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	std::vector<unsigned char>* pvMask = NULL;
	std::vector<unsigned char>* pvData = NULL;
	//copy the data in pcfv at iMaskStart to iMaskStart+4 to another vector
	try {
		vector<unsigned char>::const_iterator first = pv->begin() + iMaskStart;
		vector<unsigned char>::const_iterator last = pv->begin() + (iMaskStart + 4);
		pvMask = new std::vector<unsigned char>(first,last);
	}
	catch (std::out_of_range) {
		cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR Could not instantiate pvMask - out of range." << endl;
		return;
	}
	catch (...) {
		cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR Could not instantiate pvMask - Error unknown." << endl;
		return;
	}
	//copy the data in pcfv at iDataStart to end() to another vector
	int iSize = pv->size();
	if ((iDataStart + WSPayloadLength) > (pv->size() - 1)) {
		//cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR iDataStart + WSPayloadLength: " << iDataStart + WSPayloadLength <<
			//" pv->size-1: " << pv->size() - 1 << endl;
		iEndData = pv->size() - 1;
	}
	else {
		iEndData = iDataStart + WSPayloadLength;
	}
	try {
		vector<unsigned char>::const_iterator first = pv->begin() + iDataStart;
		vector<unsigned char>::const_iterator last = pv->begin() + iEndData;
		pvData = new std::vector<unsigned char>(first,last);
	}
	catch (std::out_of_range) {
		cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR Could not instantiate pvData - out of range." << endl;
		delete pvMask;
		return;
	}
	catch (...) {
		cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR Could not instantiate pvData - Error unknown." << endl;
		delete pvMask;
		return;
	}
	//cout << "Size of pvMask: " << pvMask->size() << " Size of pvData: " << pvData->size() << endl;
	//*errorf << "AnalyzeWebSocketFrameVector:" << std::endl;
	int interateSize = iEndData - iDataStart;
	try {
		for (int i = 0;i < interateSize; i++) {
			unsigned char key = pvMask->at(i % 4);
			unsigned char masked = pvData->at(i);
			unsigned char unmasked = masked ^ key;
			//char cpTemp[128];
			//sprintf(cpTemp, "%d Key: 0x%x Masked: 0x%x Unmasked: %c\n", i, key, masked, unmasked);
			//*errorf << cpTemp;
			strp->push_back(unmasked);
		}
	}
	catch (std::out_of_range) {
		cout << "AnalyzeWebsocketFrameVector::DecodePayload: ERROR while decoding - out of range." << endl;
	}
	if (pvMask != NULL)
		delete pvMask;
	if (pvData != NULL)
		delete pvData;
}
