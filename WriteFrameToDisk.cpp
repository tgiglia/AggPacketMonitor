#include "pch.h"
#include "WriteFrameToDisk.h"


WriteFrameToDisk::WriteFrameToDisk(std::string path) {
	sFilePath = path;
	ullFrameNumber = 0;
	outf = NULL;
	fileOpened = false;
}

WriteFrameToDisk::~WriteFrameToDisk() {
	if (fileOpened) {
		delete outf;
	}
}

bool WriteFrameToDisk::saveFrameToDisk(unsigned int uiLen, const u_char* pkt_data, const char* cpTag) {
	int iRowCnt = 0;
	char cpTemp[256];
	memset(cpTemp, sizeof(cpTemp), 0);
	ullFrameNumber++;
	if (!fileOpened) {
		outf = new std::ofstream(sFilePath);
		if (!outf) {
			std::cout << "WriteFrameToDisk::saveFrameToDisk: Error we could not open " << sFilePath<<" for writing."<<std::endl;
			return false;
		}
		fileOpened = true;
	}
	//create the array declaration
	sprintf_s(cpTemp, sizeof(cpTemp), "static const unsigned char %s%ld[%u]={\n",cpTag, ullFrameNumber,uiLen);
	*outf << cpTemp;
	memset(cpTemp, sizeof(cpTemp), 0);
	for (unsigned int i = 0;i < uiLen;i++) {
		if (i < uiLen - 1) {
			sprintf_s(cpTemp, sizeof(cpTemp), "0x%x,", pkt_data[i]);
		}
		else {
			sprintf_s(cpTemp, sizeof(cpTemp), "0x%x\n", pkt_data[i]);
		}
		*outf << cpTemp;
		iRowCnt++;
		if (iRowCnt >= iRowSz) {
			*outf << std::endl;
			iRowCnt = 0;
		}
	}

	*outf << "};" << std::endl;
	outf->flush();
}
