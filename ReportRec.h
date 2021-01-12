#pragma once
#include <iostream>
#include<map>
#include<queue>
#include<thread>
#include<mutex>
#include <iterator>
#include <Windows.h>
#include "AnaylyzeWebsocketFrame.h"
#include <string>

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

class PNCReportMap : public MTReportRecMap {
protected:
	unsigned __int64 rawDistinctReadIds;
	unsigned __int64 rawDuplicateMessages;
	unsigned __int64 rawDuplicateReads;
	float percentReadsDuplicated;
	std::string sPath;
public:
	PNCReportMap(const char* path) : MTReportRecMap(){
		rawDistinctReadIds = 0;
		rawDuplicateMessages = 0;
		percentReadsDuplicated = 0;
		rawDuplicateReads = 0;
		sPath = path;
	}
	unsigned __int64 rtRawDistinctReadIds() { return rawDistinctReadIds; }
	unsigned __int64 rtDuplicateMessages() { return rawDuplicateMessages; }
	unsigned __int64 rtRawDuplicateReads() { return rawDuplicateReads; }
	float rtPercentReadsDuplicated() { return percentReadsDuplicated; }
	bool calculateDups();
	bool writeDupsToFile();
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