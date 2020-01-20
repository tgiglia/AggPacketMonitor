#include "pch.h"
#include "PcapFrame.h"
#include<chrono>

using namespace std;
using namespace std::chrono;

constexpr milliseconds timespecToDuration(struct pcap_pkthdr headerData) {
	auto duration = seconds{ headerData.ts.tv_sec } + microseconds{ headerData.ts.tv_usec };
	return std::chrono::duration_cast<std::chrono::milliseconds>(duration);
}

PCapFrameVector::PCapFrameVector(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (pkt_data == NULL) {
		cout << "PCapFrameVector::PCapFrameVector: ERROR pkt_data is NULL!" << endl;
		return;
	}
	timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	vPktData.insert(vPktData.end(), &pkt_data[0], &pkt_data[header->caplen]);
	headerData.caplen = header->caplen;
	headerData.len = header->len;
	headerData.ts.tv_sec = header->ts.tv_sec;
	headerData.ts.tv_usec = header->ts.tv_usec;
}

PCapFrameVector::PCapFrameVector(const PCapFrameVector& obj) {
	vPktData.clear();
	copy(obj.vPktData.begin(), obj.vPktData.end(), back_inserter(vPktData));
	timeStamp = obj.timeStamp;
	headerData.caplen = obj.headerData.caplen;
	headerData.len = obj.headerData.len;
	headerData.ts.tv_sec = obj.headerData.ts.tv_sec;
	headerData.ts.tv_usec = obj.headerData.ts.tv_usec;

}

void PCapFrameVector::setObject(PCapFrameVector& obj) {
	vPktData.clear();
	copy(obj.vPktData.begin(), obj.vPktData.end(), back_inserter(vPktData));
	timeStamp = obj.timeStamp;
	headerData.caplen = obj.headerData.caplen;
	headerData.len = obj.headerData.len;
	headerData.ts.tv_sec = obj.headerData.ts.tv_sec;
	headerData.ts.tv_usec = obj.headerData.ts.tv_usec;
}


PcapFrame::PcapFrame(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (pkt_data == NULL) {
		cout << "PcapFrame::PcapFrame: ERROR pkt_data is NULL!" << endl;
		return;
	}
	//cout << "PcapFrame Constructor called." << endl;
	unsigned __int64 timeStamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	//cout << "PcapFrame::PcapFrame: caplen: " << header->caplen << " len: " << header->len;
	cpPktData = new unsigned char[header->caplen + 128];
	
	headerData.caplen = header->caplen;
	headerData.len = header->len;
	headerData.ts.tv_sec = header->ts.tv_sec;
	headerData.ts.tv_usec = header->ts.tv_usec;
	memset(cpPktData, header->caplen + 1, 0);
	memmove(cpPktData,pkt_data, headerData.caplen);
	//cout << "PcapFrame::PcapFrame: done. " << endl;
}



PcapFrame::PcapFrame(const PcapFrame& obj) {
	
	//cout << "PcapFrame Copy Constructor called." << endl;
	cpPktData = cpPktData = new unsigned char[obj.headerData.caplen + 128];
	
	timeStamp = obj.timeStamp;
	headerData.caplen = obj.headerData.caplen;
	headerData.len = obj.headerData.len;
	headerData.ts.tv_sec = obj.headerData.ts.tv_sec;
	headerData.ts.tv_usec = obj.headerData.ts.tv_usec;
	memset(this->cpPktData, obj.headerData.caplen, 0);
	memmove(this->cpPktData, obj.cpPktData, obj.headerData.caplen);
	
}

void PcapFrame::setObject(PcapFrame& obj) {
	//cout << "PcapFrame setObject called." << endl;
	cpPktData = cpPktData = new unsigned char[obj.headerData.caplen + 128];
	timeStamp = obj.timeStamp;
	headerData.caplen = obj.headerData.caplen;
	headerData.len = obj.headerData.len;
	headerData.ts.tv_sec = obj.headerData.ts.tv_sec;
	headerData.ts.tv_usec = obj.headerData.ts.tv_usec;
	memset(this->cpPktData, obj.headerData.caplen, 0);
	memmove(this->cpPktData, obj.cpPktData, obj.headerData.caplen);
}

PcapFrame::~PcapFrame() {
	if (cpPktData != NULL) {
		//cout << "PcapFrame::~PcapFrame called." << endl;
		delete[] cpPktData;
		cpPktData = NULL;
	}
}

MTPcapFrameVectorQueue::MTPcapFrameVectorQueue() {
	hMutex = CreateMutexW(NULL, TRUE, NULL);
	if (hMutex == NULL) {
		std::cout << "MTPcapFrameVectorQueue: failed to create mutex: " << GetLastError() << std::endl;
		return;
	}
	ReleaseMutex(hMutex);
}

MTPcapFrameVectorQueue::~MTPcapFrameVectorQueue() {
	CloseHandle(hMutex);
}


bool MTPcapFrameVectorQueue::getNextElement(PCapFrameVector& pf) {
	bool rt = true;
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			if (frameQueue.empty()) {
				rt = false;
			}
			else {
				PCapFrameVector pfTmp = frameQueue.front();
				pf.setObject(pfTmp);
				frameQueue.pop();
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameQueue::getNextElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::getNextElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::getNextElement WAIT_TIMEOUT" << endl;
		return false;

	}
	return rt;
}

bool MTPcapFrameVectorQueue::addElement(PCapFrameVector& pf) {
	bool rt = true;
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			frameQueue.push(pf);
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameVectorQueue::addElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::addElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::addElement WAIT_TIMEOUT" << endl;
		return false;
	}
	return rt;
}

unsigned long long MTPcapFrameVectorQueue::getSize() {
	DWORD dwWaitResult;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			return frameQueue.size();
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameVectorQueue::getSize: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameVectorQueue::getSize: WAIT_ABANDONED" << endl;
		break;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameVectorQueue::getSize WAIT_TIMEOUT" << endl;
		break;
	}
	return 0;
}

MTPcapFrameQueue::MTPcapFrameQueue() {
	hMutex = CreateMutexW(NULL, TRUE, NULL);
	if (hMutex == NULL) {
		std::cout << "ERROR! MTPcapFrameQueue: failed to create mutex: " << GetLastError() << std::endl;
	}
	ReleaseMutex(hMutex);
	frameQueue = new std::queue<PcapFrame>();
}

MTPcapFrameQueue::~MTPcapFrameQueue() {
	CloseHandle(hMutex);
	if (frameQueue != NULL) {
		delete frameQueue;
	}
}


bool MTPcapFrameQueue::getNextElement(PcapFrame& pf) {
	bool rt = true;
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			if (frameQueue->empty()) {
				rt = false;
			}
			else {
				PcapFrame pfTmp = frameQueue->front();
				pf.setObject(pfTmp);
				frameQueue->pop();
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameQueue::getNextElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::getNextElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::getNextElement WAIT_TIMEOUT" << endl;
		return false;

	}
	return rt;
}

bool MTPcapFrameQueue::addElement(PcapFrame& pf) {
	bool rt = true;
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			frameQueue->push(pf);
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameQueue::addElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::addElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::addElement WAIT_TIMEOUT" << endl;
		return false;
	}
	return rt;
}

bool MTPcapFrameQueue::addElement(const struct pcap_pkthdr* header, const u_char* pkt_data) {
	bool rt = true;
	DWORD dwWaitResult;

	if (header == NULL) {
		cout << "MTPcapFrameQueue::addElement: ERROR header is null" << endl;
		return false;
	}
	if (pkt_data == NULL) {
		cout << "MTPcapFrameQueue::addElement: ERROR pkt_data is null" << endl;
		return false;
	}
	
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			//cout << "MTPcapFrameQueue::addElement: before pushing to queue." << endl;
			PcapFrame* pf = new PcapFrame(header, pkt_data);
			frameQueue->push(*pf);
			delete pf;
			//cout << "MTPcapFrameQueue::addElement: after pushing to queue." << endl;
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameQueue::addElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::addElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::addElement WAIT_TIMEOUT" << endl;
		return false;
	}
	//cout << "MTPcapFrameQueue::addElement: end." << endl;
	return rt;
}

unsigned long long MTPcapFrameQueue::getSize() {
	DWORD dwWaitResult;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			return frameQueue->size();
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTPcapFrameQueue::getSize: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTPcapFrameQueue::getSize: WAIT_ABANDONED" << endl;
		break;
	case WAIT_TIMEOUT:
		cout << "MTPcapFrameQueue::getSize WAIT_TIMEOUT" << endl;
		break;
	}
	return 0;
}