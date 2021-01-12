#pragma once
#include <iostream>
#include <fstream>
#include <pcap.h>
#include "PcapFrame.h"

class WriteFrameToDisk
{
protected:
	unsigned long long ullFrameNumber;
	bool fileOpened;
	const int iRowSz = 8;
	std::ofstream* outf;
	std::string sFilePath;

public:
	WriteFrameToDisk(std::string path);
	~WriteFrameToDisk();
	bool saveFrameToDisk(unsigned int uiLen,const u_char* pkt_data,const char* cpTag);
	bool saveFrameToDisk(PCapFrameVector& pcfv, const char* cpTag);
};