#pragma once
#include "PcapFrame.h"
#include "BitMasking.h"

class AnalyzeWebsocketFrameVector {
protected:
	bool isMaskSet = false;
	void DecodePayload(PCapFrameVector& pcfv, std::string* strp, u_int uiPayloadLocation,int iMaskStart,int iDataStart, 
		unsigned long long WSPayloadLength);
public:
	AnalyzeWebsocketFrameVector() {};
	void AnalyzeFrame(PCapFrameVector& pcfv, std::string* strp, u_int uiPayloadLocation);

};


