#include "pch.h"
#include "ReportRec.h"

using namespace std;

MTReportRecMap::MTReportRecMap() {
	hMutex = CreateMutexW(NULL, TRUE, NULL);
	if (hMutex == NULL) {
		std::cout << "ERROR! MTReportRecMap: failed to create mutex: " << GetLastError() << std::endl;
	}
	ReleaseMutex(hMutex);

	aggMap = new std::map<std::string, ReadInfo>();

}

MTReportRecMap::~MTReportRecMap() {
	CloseHandle(hMutex);
	if (aggMap != NULL) {
		delete aggMap;
	}
		
}

bool MTReportRecMap::insertRec(ReadInfo& ri) {
	DWORD dwWaitResult;
	bool rt = true;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			std::pair<std::map<std::string, ReadInfo>::iterator, bool> result = 
				aggMap->insert(std::make_pair<std::string, ReadInfo>(std::string(ri.getId()),
				ReadInfo(ri.getId(), ri.getTimeStamp())));
			if (!result.second) {
				rt = false;
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecMap::insertRec: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecMap::insertRec: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTReportRecMap::insertRec WAIT_TIMEOUT" << endl;
		return false;
	default:
		cout << "MTReportRecMap::insertRec: WaitForSingleObject failed: " << dwWaitResult << endl;
		return false;
	}
	return rt;
}

bool MTReportRecMap::isThere(std::string id, unsigned __int64& timestamp) {
	DWORD dwWaitResult;
	bool rt = true;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			std::map<std::string, ReadInfo>::iterator aggIt;
			aggIt = aggMap->find(id);
			if (aggIt != aggMap->end()) {
				ReadInfo r = aggIt->second;
				timestamp = r.getTimeStamp();
			}
			else {
				rt = false;
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecMap::isThere: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecMap::isThere: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTReportRecMap::isThere WAIT_TIMEOUT" << endl;
		return false;
	}
	return rt;
}

bool MTReportRecMap::erase(std::string id) {
	DWORD dwWaitResult;
	bool rt = true;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			int iErase = aggMap->erase(id);
			if (iErase < 1) {
				cout << id << " was not erased." << endl;
				rt = false;
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecMap::erase: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecMap::erase: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTReportRecMap::erase WAIT_TIMEOUT" << endl;
		return false;
	}

	return rt;
}

unsigned long long MTReportRecMap::getSize() {
	DWORD dwWaitResult;
	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			return aggMap->size();
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecMap::erase: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecMap::erase: WAIT_ABANDONED" << endl;
		break;
	case WAIT_TIMEOUT:
		cout << "MTReportRecMap::erase WAIT_TIMEOUT" << endl;
		break;
	}
	return 0;
}

MTReportRecQueue::MTReportRecQueue() {
	hMutex = CreateMutexW(NULL, TRUE, NULL);
	if (hMutex == NULL) {
		std::cout << "ERROR! MTReportRecQueue: failed to create mutex: " << GetLastError() << std::endl;
	}
	ReleaseMutex(hMutex);
	recQueue = new std::queue<ReadInfo>();

}

MTReportRecQueue::~MTReportRecQueue() {
	CloseHandle(hMutex);
	if (recQueue != NULL) {
		delete recQueue;
	}
}

bool MTReportRecQueue::getNextElement(ReadInfo& ri) {
	bool rt = true;
	DWORD dwWaitResult;

	dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			if (recQueue->empty()) {
				rt = false;
			}
			else {
				ri = recQueue->front();
				recQueue->pop();
			}
		}
		finally {
			if (!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecQueue::getNextElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecQueue::getNextElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTReportRecQueue::getNextElement WAIT_TIMEOUT" << endl;
		return false;

	}
	return rt;
}

bool MTReportRecQueue::addElement(ReadInfo& ri) {
	bool rt = true;

	DWORD dwWaitResult = WaitForSingleObject(hMutex, 1000);
	switch (dwWaitResult) {
	case WAIT_OBJECT_0:
		try {
			recQueue->push(ri);
		}
		finally {
			if(!ReleaseMutex(hMutex)) {
				cout << "ERROR! MTReportRecQueue::addElement: Could not release mutex." << endl;
			}
		}
		break;
	case WAIT_ABANDONED:
		cout << "MTReportRecQueue::addElement: WAIT_ABANDONED" << endl;
		return false;
	case WAIT_TIMEOUT:
		cout << "MTReportRecQueue::addElement WAIT_TIMEOUT" << endl;
		return false;
	}

	return rt;
}