#pragma once
#include<iostream>
#include<string>

class APMConfig {
private:
	static APMConfig* instance;
	std::string sPacketFilter;
	std::string sAggregatorIP;
	std::string sPNCIP;
	std::string SniffType;
	unsigned short usAggPort;
	unsigned short usPncPort;
	APMConfig() {}
public:
	static APMConfig* getInstance();
	std::string rtPacketFilter() { return sPacketFilter; }
	std::string rtAggregatorIP() { return sAggregatorIP; }
	std::string rtPNCIP() { return sPNCIP; }
	std::string rtSniffType() { return SniffType; }
	unsigned short rtAggPort() { return usAggPort; }
	unsigned short rtusPncPort() { return usPncPort; }
	bool loadConfig();
	void showConfig();
};



