#pragma once
#include<iostream>
#include "BitMasking.h"


class WSFirstByteDecoder
{
protected:
	BYTE b;
public:
	WSFirstByteDecoder(BYTE first) { b = first; }
	bool finalFragment();
	void getOpCode(std::string &s);
	void showByte();
};