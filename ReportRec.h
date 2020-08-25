#pragma once
#include <iostream>
#include<map>
#include<queue>
#include<thread>
#include<mutex>
#include <iterator>
#include <Windows.h>
#include "AnaylyzeWebsocketFrame.h"

typedef struct reportRec
{
	char cpId[64];
	unsigned __int64 readTimeStamp;
	unsigned __int64 pncTimeStamp;
}reportRec;

class MTReportRecMap {
protected:
	HANDLE hMutex;
	std::map<std::string, ReadInfo> *aggMap=NULL;
public:
	MTReportRecMap();
	~MTReportRecMap();
	bool insertRec(ReadInfo& ri);
	bool isThere(std::string id, unsigned __int64& timestamp);
	bool erase(std::string id);
	bool saveMapToDisk(std::ofstream* outfile);
	unsigned long long getSize();
};

class MTReportRecQueue {
protected:
	HANDLE hMutex;
	std::queue<ReadInfo> *recQueue;
public:
	MTReportRecQueue();
	~MTReportRecQueue();
	bool getNextElement(ReadInfo& ri);
	bool addElement(ReadInfo& ri);
};