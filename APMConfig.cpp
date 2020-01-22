#include "pch.h"
#include "APMConfig.h"

using namespace System;
using namespace std;

APMConfig* APMConfig::instance = NULL;

APMConfig* APMConfig::getInstance() {
	if (instance == NULL) {
		instance = new APMConfig;
		return instance;
	}
	return instance;
}

bool APMConfig::loadConfig() {
	char cpTemp[256];
	try {
		String^ packetFilter = Configuration::ConfigurationManager::AppSettings["packetFilter"];
		sprintf_s(cpTemp, sizeof(cpTemp), "%s", packetFilter->ToString());
		sPacketFilter = cpTemp;

		String^ AggregatorIP = Configuration::ConfigurationManager::AppSettings["AggregatorIP"];
		sprintf_s(cpTemp, sizeof(cpTemp), "%s", AggregatorIP->ToString());
		sAggregatorIP = cpTemp;

		String^ PNCIP = Configuration::ConfigurationManager::AppSettings["PNCIP"];
		sprintf_s(cpTemp, sizeof(cpTemp), "%s", PNCIP->ToString());
		sPNCIP = cpTemp;

		String^ AggPort = Configuration::ConfigurationManager::AppSettings["AggPort"];
		sprintf_s(cpTemp, sizeof(cpTemp), "%s", AggPort->ToString());
		usAggPort = std::stoi(cpTemp);

		String^ PncPort = Configuration::ConfigurationManager::AppSettings["PncPort"];
		sprintf_s(cpTemp, sizeof(cpTemp), "%s", PncPort->ToString());
		usPncPort = std::stoi(cpTemp);
	}
	catch (...) {
		std::cout << "APMConfig::loadConfig: ERROR. Loading the configuration threw a error." << std::endl;
		return false;
	}

	
	return true;
}

void APMConfig::showConfig() {
	cout << "Filter: " << sPacketFilter << endl;
	cout << "sAggregatorIP: " << sAggregatorIP << endl;
	cout << "sPNCIP: " << sPNCIP << endl;
	cout << "usAggPort: " << usAggPort << endl;
	cout << "usPncPort: " << usPncPort << endl;
}