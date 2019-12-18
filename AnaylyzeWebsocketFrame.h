#pragma once
#include "BitMasking.h"
#include <iostream>



class AnalyzeWebSocketFrame {
protected:
	
	unsigned char* frame=NULL;
	int fLen=0;
	bool isMaskSet = false;
	char *cpPayload=NULL;

	const char *DecodePayload(unsigned char* ucpMask, unsigned char* ucpPayload, int iLen);
	void DecodePayload(unsigned char* ucpMask, unsigned char* ucpPayload, int iLen,std::string *strp);

public:
	AnalyzeWebSocketFrame(unsigned char* f, int len);
	~AnalyzeWebSocketFrame() { if (cpPayload != NULL) delete cpPayload; };
	void ShowMe();
	void AnalyzeFrame();
	void AnalyzeFrame(std::string *strp);
};

