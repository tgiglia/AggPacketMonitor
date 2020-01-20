#pragma once
#include<iostream>


class TrackGarbledMessages
{
protected:
	unsigned long long ullCnt;
	float fPercentageThreshold;
public:
	TrackGarbledMessages(float f) { fPercentageThreshold = f; ullCnt = 0; }
	bool isMessageGarbled(std::string& s);
	unsigned long long rtCnt() { return ullCnt; }
};