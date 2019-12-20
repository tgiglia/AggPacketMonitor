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

class ReadInfo {
	std::string m_id;
	unsigned __int64 timeStamp;
public:
	ReadInfo(std::string s, unsigned __int64 t) : m_id(s),timeStamp(t) {}
	const std::string& getId() const { return m_id; } 
	unsigned __int64 getTimeStamp() { return timeStamp; }
	bool operator== (const ReadInfo& ri) const
	{
		if (m_id.compare(ri.m_id) == 0)
			return true;
		return false;
	}
	bool operator< (const ReadInfo& uo) const
	{
		if (uo.timeStamp < this->timeStamp)
			return true;
		return false;
	}
};

struct ReadInfoComparator
{
	bool operator()(const ReadInfo& left, const ReadInfo& right) const
	{
		std::string leftStr = left.getId();
		std::string rightStr = right.getId();
		if (leftStr.compare(rightStr) == 0)
			return true;

		return false;
	}
};

class User
{
	std::string m_id;
	std::string m_name;
public:
	User(std::string name, std::string id)
		:m_id(id), m_name(name)
	{}
	std::string& getId()  {
		return m_id;
	}
	std::string& getName()  {
		return m_name;
	}
	bool operator< (const User& userObj) const
	{
		if (userObj.m_id < this->m_id)
			return true;
		return false;
	}
};



