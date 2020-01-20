#pragma once

#include<iostream>
#include "pcap.h"
#include<queue>
#include<thread>
#include<mutex>
#include<vector>
#include <Windows.h>

class PcapFrame {
protected:
	unsigned __int64 timeStamp;
	struct pcap_pkthdr headerData;
	unsigned char* cpPktData=NULL;
	
public:
	PcapFrame(const struct pcap_pkthdr* header, const u_char* pkt_data);
	PcapFrame(){}
	PcapFrame(const PcapFrame& obj);//Copy Constructor
	~PcapFrame();
	unsigned __int64 rtTimeStamp() { return timeStamp; }
	unsigned char* rtPktData() { return cpPktData; }
	pcap_pkthdr rtHeader() { return headerData; }
	void setObject(PcapFrame& obj);
};

class PCapFrameVector {
protected:
	unsigned __int64 timeStamp;
	struct pcap_pkthdr headerData;
	std::vector<unsigned char> vPktData;

public:
	PCapFrameVector(const struct pcap_pkthdr* header, const u_char* pkt_data);
	PCapFrameVector(const PCapFrameVector& obj);
	PCapFrameVector() {};
	unsigned __int64 rtTimeStamp() { return timeStamp; }
	pcap_pkthdr rtHeader() { return headerData; }
	void setObject(PCapFrameVector& obj);
	std::vector<unsigned char>* rtPktData() { return &vPktData; }

};

class MTPcapFrameVectorQueue {
protected:
	HANDLE hMutex;
	std::queue< PCapFrameVector> frameQueue;
public:
	MTPcapFrameVectorQueue();
	~MTPcapFrameVectorQueue();
	bool getNextElement(PCapFrameVector& pf);
	bool addElement(PCapFrameVector& pf);
	unsigned long long getSize();
};

class MTPcapFrameQueue {
protected:
	HANDLE hMutex;
	std::queue<PcapFrame>* frameQueue;
public:
	MTPcapFrameQueue();
	~MTPcapFrameQueue();
	bool getNextElement(PcapFrame& pf);
	bool addElement(PcapFrame& pf);
	bool addElement(const struct pcap_pkthdr* header, const u_char* pkt_data);
	unsigned long long getSize();
};