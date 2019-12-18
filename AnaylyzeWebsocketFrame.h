#pragma once
#include "BitMasking.h"
#include <iostream>
#include <string.h>

class AnalyzeWebSocketFrame {
protected:
	
	unsigned char* frame=NULL;
	int fLen=0;
	bool isMaskSet = false;
	char *cpPayload=NULL;

	const char *DecodePayload(unsigned char* ucpMask, unsigned char* ucpPayload, int iLen);
public:
	AnalyzeWebSocketFrame(unsigned char* f, int len);
	~AnalyzeWebSocketFrame() { if (frame != NULL) delete frame; if (cpPayload != NULL) delete cpPayload; };
	void ShowMe();
	void AnalyzeFrame();
};

