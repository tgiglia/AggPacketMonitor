#include "pch.h"
#include <pcap.h>
#include <chrono>
#include <iostream>
#include <map>
#include <iterator>
#include <fstream>
#include "AnaylyzeWebsocketFrame.h"
#include "AnalyzeWebSocketFrameVector.h"
#include "concurrent_queue.h"
#include "WSFirstByteDecoder.h"
#include "WriteFrameToDisk.h"
#include "TcpFrameInspector.h"
#include "Frames.h"
#include "PcapFrame.h"
#include "TrackGarbledMessages.h"
#include "ReportRec.h"
#include "APMConfig.h"
int runNpcap();

using namespace System;
#ifdef WIN32
#include <tchar.h>
BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif



typedef struct idType
{
	char cpId[64];
}idType;




void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void pnc_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void packet_producer(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void printBits(size_t const size, void const* const ptr);
int isStandard(unsigned char c);
void showPayloadData(u_char* ucp, int num);
void AggregatorProcessor(unsigned __int64 timeStamp, ip_header *ih, tcp_header *tcpH, u_char* ucpPayload, 
	u_short dataLen);
void PNCProcessor(unsigned __int64 timeStamp, ip_header* ih, tcp_header* tcpH, u_char* ucpPayload,
	u_short dataLen,u_short frameLength, const u_char* pkt_data);
void PNCReporter(ReadInfo read, ReadInfo pnc);
void PNCReporter2(ReadInfo read, ReadInfo pnc, TrackGarbledMessages& tgm);
void AlarmReporter(ReadInfo read, ReadInfo pnc, TrackGarbledMessages& tgm);
void writeBadPacket(std::string* strp,char* cp);
void writeBadAggPacket(char* cp, int dataLen);
void writeMapSize(unsigned long ulBefore, unsigned long ulAfter);
void writeAggInsert(ReadInfo ri);
void writePncCheckError(u_short ipDataLen, u_int uiPayloadLocation, u_int ip_len, u_int uiTcpHeaderSize, unsigned int uiHeaderLen,
	unsigned int uiCapLen,unsigned char c);
void analyzeWebSocketFrame(const unsigned char *pkt_data, int len);
void analyzeIPv6Frame(const unsigned char* pkt_data, int len);
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType);
DWORD WINAPI PacketConsumer(LPVOID lpParam);
void packet_consumer_vector(PCapFrameVector& pcfv);
void packet_consumer_vector_pnc(PCapFrameVector& pcfv);
void packet_consumer_duplicate_readalarm_vector(PCapFrameVector& pcfv);
void packet_consumer_readalarm(PCapFrameVector& pcfv);
void packet_consumer_injector(PCapFrameVector& pcfv);
void packet_consumer_homeagg(PCapFrameVector& pcfv);
void packet_consumer_debugger(PCapFrameVector& pcfv);
void WSProcessorVector(PCapFrameVector& pcfv, u_int uiPayloadLocation);
void WSProcessorPNCVector(PCapFrameVector& pcfv, u_int uiPayloadLocation);
void WSAlarmProcessorPNCVector(PCapFrameVector& pcfv, u_int uiPayloadLocation);
void WSAggAlarmProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation,time_t timeStamp);
void AggregatorProcessorVector(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp);
void HomeAggregatorProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, time_t timeStamp);
void RESTAlarmProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp);
void InjectorProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp);
bool setAnalysisFunction(APMConfig* pConfig);

std::map<ReadInfo,int> readsMap;
//std::map<std::string, ReadInfo> aggMap;
MTReportRecMap* pAggRecMap;
PNCReportMap* pPNCRecMap;
PNCReportMap* pPNCAlarmMap;

MTPcapFrameVectorQueue* pframeQueueVector;

char cpAggregatorIP[64];
char cpPNCIP[64];
u_short usAggPort = 80;
u_short usPncPort = 8100;
//concurrent_queue<reportRec>* reportQueue;
unsigned long long ullTotal = 0;
unsigned long long ullLowTarget = 1500;
unsigned long long ullMidTarget = 2250;
unsigned long long ullHighTarget = 3750;
unsigned long long ullAlrmLowTarget = 2000;
unsigned long long ullAlrmMidTarget = 3000;
unsigned long long ullAlrmHighTarget = 5000;
unsigned long long ullReadCnt = 0;
unsigned long long ullReadInsertFail = 0;
unsigned long long ullPNCCnt = 0;
unsigned long long ullAlarmCnt = 0;
unsigned long long ullNoId;
unsigned long long ullCntrl;
unsigned long long ullNoDecode;
unsigned long long ullWSCntrl;
unsigned long long ullAddFail;
unsigned long long ullAddedElements;
unsigned long long ullNoMatchId;
unsigned long long ullNoFindPutRead;
int iLowTargetCnt = 0;
int iMidTargetCnt = 0;
int iHighTargetCnt = 0;
int iAlrmLowTargetCnt = 0;
int iAlrmMidTargetCnt = 0;
int iAlrmHighTargetCnt = 0;
int iSampleCount;

std::ofstream* outf;
std::ofstream* errorf;
std::ofstream* aggErrorf;
std::ofstream* pncErrorf;
std::ofstream* queueContents;
std::ofstream* homeAggReadFile;
std::ofstream* readAlarmLatency;

WriteFrameToDisk* wftd;
TrackGarbledMessages* tgmp;

int iClassType=0;

void showCurrentTime();
template<typename T>
void print_time(std::chrono::time_point<T> time);
template<typename T>
void writeAggReadData(char* cpID, time_t t, std::chrono::time_point<T> time);

void (*fun_ptr) (PCapFrameVector& pcfv) = NULL;

int main(array<System::String ^> ^args)
{
	//std::cout << "AggPacketMonitor started!" << std::endl;
	APMConfig* pConfig = pConfig->getInstance();
	if (pConfig->loadConfig()) {
		pConfig->showConfig();
	}
	else {
		std::cout << "ERROR Could Not Load Configuration. Exiting." << std::endl;
		return 0;
	}
	if (!setAnalysisFunction(pConfig)) {
		return 0;
	}
	tgmp = new TrackGarbledMessages(.50);
	pAggRecMap = new MTReportRecMap();
	pPNCRecMap = new PNCReportMap("DuplicateReads.csv");
	pPNCAlarmMap = new PNCReportMap("DuplicateAlarms.csv");

	ullNoId = 0;
	ullCntrl = 0;
	ullNoDecode = 0;
	ullCntrl = 0;
	ullWSCntrl = 0;
	ullAddFail = 0;
	ullAddedElements = 0;
	ullNoMatchId = 0;
	ullNoFindPutRead = 0;
	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
	{
		std::cout << "ERROR, could not install Control Handler." << std::endl;
		return 0;
	}
	
	/*bool b = true;
	if (b) {
		
		analyzeIPv6Frame((unsigned char*)pncdupprocesser1, 80);
		return 0;
	}*/
	//analyzeWebSocketFrame((unsigned char *)ctrlMsg2, 60);
	//analyzeWebSocketFrame((unsigned char*)ctrlMsg3, 63);
	//analyzeWebSocketFrame((unsigned char*)Msg4, 1170);
	//analyzeWebSocketFrame((unsigned char*)noFindId19, 2487);
	//analyzeWebSocketFrame((unsigned char*)ctrlMsg5, 54);
	//analyzeWebSocketFrame((unsigned char*)noFindId20, 457);
	//analyzeWebSocketFrame((unsigned char*)noFindId21, 392);
	//analyzeWebSocketFrame((unsigned char*)ctrlMsg5, 63);
	pframeQueueVector = new MTPcapFrameVectorQueue();
	DWORD dwThread;
	
	showCurrentTime();

	HANDLE h = CreateThread(NULL, 0, PacketConsumer, NULL, 0, &dwThread);
	runNpcap();
	delete pAggRecMap;
	delete pPNCRecMap;
	delete pPNCAlarmMap;
	delete tgmp;
	delete pframeQueueVector;
	
	std::cout << "AggPacketMonitor terminating." << std::endl;
    return 0;
}

void showCurrentTime() {
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	

	print_time(now);
	
	
}

template<typename T>
void writeAggReadData(char *cpID,time_t t,std::chrono::time_point<T> time) {
	using namespace std;
	using namespace std::chrono;
	char cpTemp[100];
	char cpLine[128];

	strftime(cpTemp, sizeof(cpTemp), "%Y-%m-%d %H:%M:%S", localtime(&t));
	typename T::duration since_epoch = time.time_since_epoch();
	seconds s = duration_cast<seconds>(since_epoch);
	since_epoch -= s;
	milliseconds milli = duration_cast<milliseconds>(since_epoch);
	sprintf_s(cpLine, sizeof(cpLine), "%s.%lld", cpTemp, milli.count());
	*homeAggReadFile << cpLine << "," << cpID << std::endl;

}

template<typename T>
void print_time(std::chrono::time_point<T> time) {
	using namespace std;
	using namespace std::chrono;

	time_t curr_time = T::to_time_t(time);
	char sRep[100];
	strftime(sRep, sizeof(sRep), "%Y-%m-%d %H:%M:%S", localtime(&curr_time));
	
	typename T::duration since_epoch = time.time_since_epoch();
	seconds s = duration_cast<seconds>(since_epoch);
	since_epoch -= s;
	milliseconds milli = duration_cast<milliseconds>(since_epoch);
	cout << '[' << sRep << ":" << milli.count() << "]\n";
}

bool setAnalysisFunction(APMConfig* pConfig) {
	if (pConfig->rtSniffType().compare("websocketlatency") == 0) {
		fun_ptr = &packet_consumer_vector;
		iClassType = 1;
		return true;
	}
	if (pConfig->rtSniffType().compare("alarmlatency") == 0) {
		fun_ptr = &packet_consumer_readalarm;
		iClassType = 2;
		return true;
	}
	if (pConfig->rtSniffType().compare("injectorprocessor") == 0) {
		fun_ptr = &packet_consumer_injector;
		iClassType = 3;
		return true;
	}
	if (pConfig->rtSniffType().compare("homeaggprocessor") == 0) {
		fun_ptr = &packet_consumer_homeagg;
		iClassType = 4;
		return true;
	}
	if (pConfig->rtSniffType().compare("pncdupprocessor") == 0) {
		fun_ptr = &packet_consumer_vector_pnc;
		iClassType = 5;
		return true;
	}
	if (pConfig->rtSniffType().compare("packet_consumer_debugger") == 0) {
		fun_ptr = &packet_consumer_debugger;
		iClassType = 5;
		return true;
	}
	if (pConfig->rtSniffType().compare("pncaggdupprocessor") == 0) {
		fun_ptr = &packet_consumer_duplicate_readalarm_vector;
		iClassType = 6;
		return true;
	}
	return false;
}
int runNpcap()
{
	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	u_int netmask;
	//char packet_filter[] = "ip and tcp and host 10.24.2.3 and dst port 8099";
	//char packet_filter[] = "ip and tcp and host 10.24.2.3 and \(dst port 8099 or dst port 8100\)"; 
	//char packet_filter[] = "ip and tcp and host 10.24.2.3 and dst port 8099";
	struct bpf_program fcode;
	unsigned short us = 5;
	APMConfig* pConfig = pConfig->getInstance();
	strcpy(cpAggregatorIP, pConfig->rtAggregatorIP().c_str());
	strcpy(cpPNCIP, pConfig->rtPNCIP().c_str());
	//strcpy(cpAggregatorIP, "10.24.2.3");
	//strcpy(cpPNCIP, "10.24.2.181");

	
	wftd = new WriteFrameToDisk("Frames.h");

	outf = new std::ofstream("output.csv");
	if (!outf) {
		std::cout << "Error we could not open output.csv for writing." << std::endl;
		return 0;
	}
	errorf = new  std::ofstream("errors.txt");
	if (!errorf) {
		std::cout << "Error we could not open errors.txt for writing." << std::endl;
		return 0;
	}
	aggErrorf = new std::ofstream("aggerrors.txt");
	if (!errorf) {
		std::cout << "Error we could not open aggerrors.txt for writing." << std::endl;
		return 0;
	}

	pncErrorf = new std::ofstream("pncCheckErrors.txt");
	if (!pncErrorf) {
		std::cout << "Error we could not open pncCheckErrors.txt for writing." << std::endl;
		return 0;
	}
	queueContents = new std::ofstream("leftoverQueueContents.txt");
	if (!queueContents) {
		std::cout << "Error we could not open leftoverQueueContents.txt for writing." << std::endl;
		return 0;
	}
	homeAggReadFile = new std::ofstream("aggreads.csv");
	if (!homeAggReadFile) {
		std::cout << "Error we could not open aggreads.csv for writing." << std::endl;
		return 0;
	}
	readAlarmLatency = new std::ofstream("readAlarmLatency.csv");
	if (!readAlarmLatency) {
			std::cout << "Error we could not open readAlarmLatency.csv for writing." << std::endl;
			return 0;
	}
	
	//reportQueue = new concurrent_queue<reportRec>;

#ifdef WIN32
	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}
#endif
	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	//callAObject(us);
/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1;d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		100,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
	/* If the interface is without addresses we suppose to be in a C class network */
	netmask = 0xffffff;


	//compile the filter
	//printf("packet_filter = %s", packet_filter);
	printf("packet filter: %s\n", pConfig->rtPacketFilter().c_str());
	if (pcap_compile(adhandle, &fcode, pConfig->rtPacketFilter().c_str(), 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_producer, NULL);

	delete outf;
	delete errorf;
	delete aggErrorf;
	delete pncErrorf;
	delete wftd;
	delete homeAggReadFile;
	delete readAlarmLatency;

	return 0;
}

//The packet_producer's only job is to grab the packet from the wire and buffer it. The consumer thread does all the analysis
void packet_producer(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	PCapFrameVector* pfv = new PCapFrameVector(header, pkt_data);
	//std::cout << "packet_producer: got packet." << std::endl;
	pframeQueueVector->addElement(*pfv);
	delete pfv;
}

DWORD WINAPI PacketConsumer(LPVOID lpParam) {
	std::cout << "PacketConsumer thread started ..." << std::endl;
	do {
		PCapFrameVector temp;
		bool b = pframeQueueVector->getNextElement(temp);
		if (b) {
			//packet_consumer_vector(temp);//handles the WinSocket sniffing.
			//packet_consumer_readalarm(temp); //handles the latency monitoring for between recieving the READ and sending the ALARM
			//packet_consumer_injector(temp);
			(*fun_ptr) (temp);
		}
	} while (1);
	return 0;
}

void packet_consumer_vector(PCapFrameVector& pcfv) {
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();
	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	strcpy(cpDestIp, tcpInspector.rtDestIp());
	iCmp = strcmp(cpDestIp, cpAggregatorIP);
	if (iCmp == 0)
	{
		iDestType = 1;
	}
	else {
		iCmp = strcmp(cpDestIp, cpPNCIP);
		if (iCmp == 0)
			iDestType = 2;
	}
	if (iDestType == 0) {//Stop processing the destination test failed
		/*printf("Destination test failed! cpDestIP: %s cpAggregatorIP: %s cpPNCIP %s Dest Port: %d\n", 
			cpDestIp, cpAggregatorIP, cpPNCIP,dport);*/
		
		return;
	}
	if (iDestType == 1 && dport != usAggPort) {
		//printf("Bad packet, dest is Agg:%s, but port is: %d\n", cpAggregatorIP, dport);
		return;
	}
	if (iDestType == 2 && dport != usPncPort) {
		//printf("Bad packet, dest is PNC:%s, but port is: %d\n", cpPNCIP, dport);
		return;
	}
	//Get a timestamp
	unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	ucpPayload = (u_char*)&ucp[uiPayloadLocation];
	//std::cout << "packet_consumer_vector: payload location is: " << uiPayloadLocation << std::endl;
	if (iDestType == 1)// This may be a PUT READ to the agg
	{
		AggregatorProcessorVector(pcfv, uiPayloadLocation, now);
		//AggregatorProcessor(now, ih, tcpH, ucpPayload, tcpInspector.rtIpDataLen() - uiPayloadLocation);
	}
	else {
		WSProcessorVector(pcfv, uiPayloadLocation);
	}
	delete[]ucp;
	
}

void packet_consumer_debugger(PCapFrameVector& pcfv) {
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;
	std::cout << "packet_consumer_debugger called!" << std::endl;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameDbg();
}

void packet_consumer_duplicate_readalarm_vector(PCapFrameVector& pcfv) {
	int iDestType = 0;
	unsigned int sequenceNum;
	
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;
	APMConfig* pConfig = pConfig->getInstance();
	//std::cout << "packet_consumer_vector_pnc called!" << std::endl;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	//wftd->saveFrameToDisk(ulPktSize, ucp, "pncdupprocesser");
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();

	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	
	
	//get the Source and Destination addresses
	unsigned char* ucpSource = tcpInspector.rtIPv6Source();
	unsigned char* ucpDest = tcpInspector.rtIPv6Dest();
	//If the Source IP is the Aggregator call WSProcessorPNCVector
	int iCmp = strcmp((const char*)ucpSource, pConfig->rtAggregatorIP().c_str());
	//std::cout << " compare of " << ucpSource << " and " << pConfig->rtAggregatorIP().c_str() << " returned " << iCmp << std::endl;
	if (iCmp == 0) {
		WSProcessorPNCVector(pcfv, uiPayloadLocation);
	}
	else {
		//If the Source address is the PNC and the Dest address is  the Aggregator call WSAlarmProcessorPNCVector
		iCmp = strcmp((const char*)ucpSource, pConfig->rtPNCIP().c_str());
		//std::cout << " compare of " << ucpSource << " and " << pConfig->rtPNCIP().c_str() << " returned " << iCmp << std::endl;
		if (iCmp == 0) {
			int iDestCmp = strcmp((const char*)ucpDest, pConfig->rtAggregatorIP().c_str());
			//std::cout << " compare of " << ucpDest << " and " << pConfig->rtAggregatorIP().c_str() << " returned " << iDestCmp << std::endl;
			if (iDestCmp == 0) {
				WSAlarmProcessorPNCVector(pcfv, uiPayloadLocation);
			}
		}
	}
	

	delete[] ucp;
}

void packet_consumer_vector_pnc(PCapFrameVector& pcfv) {
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;
	APMConfig* pConfig = pConfig->getInstance();
	//std::cout << "packet_consumer_vector_pnc called!" << std::endl;
	
	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	wftd->saveFrameToDisk(ulPktSize, ucp, "pncdupprocesser");
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();
	
	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	strcpy(cpDestIp, tcpInspector.rtDestIp());
	if (dport != pConfig->rtusPncPort()) {
		std::cout << "Dest port: " << dport << " does not equal PNC port: " << pConfig->rtusPncPort() << std::endl;
		delete[] ucp;
		return;
	}
	//std::cout << "Calling WSProcessorPNCVector with IP: " << cpDestIp << " and port: " << dport << std::endl;

	WSProcessorPNCVector(pcfv,uiPayloadLocation);

	delete[]ucp;
}

void packet_consumer_injector(PCapFrameVector& pcfv) {
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();
	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	//Get a timestamp
	unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	ucpPayload = (u_char*)&ucp[uiPayloadLocation];
	InjectorProcessor(pcfv, uiPayloadLocation,now);
}

void InjectorProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp) {
	time_t timer;
	char buffer[128];
	timer = time(NULL);
	struct tm* tm_info = localtime(&timer);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

	std::vector<unsigned char>* pv = pcfv.rtPktData();
	//std::cout << "Got packet!" << std::endl;
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message		
		//std::cout << "Got Control packet." << std::endl;
		return;
	}
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	unsigned char* ucpPayload = &ucp[uiPayloadLocation];
	char* cpUrl = strstr((char*)ucpPayload, "ReadInsertReads");
	if (cpUrl != NULL) {
		std::cout << "ReadInsertReads found: " << buffer << std::endl;
		return;
	}
	cpUrl = strstr((char*)ucpPayload, "I N S E R T");
	if (cpUrl != NULL) {
		std::cout << "INSERT found: " << buffer << std::endl;
		return;
	}
	cpUrl = strstr((char*)ucpPayload, "S E L E C T");
	if (cpUrl != NULL) {
		std::cout << "SELECT found: " << buffer << std::endl;
		return;
	}
	writeBadAggPacket((char*)ucpPayload, pv->size() - uiPayloadLocation);
}


void packet_consumer_homeagg(PCapFrameVector& pcfv) 
{
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();
	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	strcpy(cpDestIp, tcpInspector.rtDestIp());

	if (dport == usAggPort) {
		iDestType = 1;
	}
	
	
	
	//Get a timestamp
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	std::chrono::system_clock::duration tp = now.time_since_epoch();
	tp -= std::chrono::duration_cast<std::chrono::seconds>(tp);
	time_t tt = std::chrono::system_clock::to_time_t(now);
	//Set the payload
	ucpPayload = (u_char*)&ucp[uiPayloadLocation];
	if (iDestType == 1)// This may be a PUT READ to the agg
	{
		printf("\tINGRESS PACKET. Dest: %s sport: %d  dport = %d packetSize = %d\n",cpDestIp,sport,dport, ulPktSize);
		HomeAggregatorProcessor(pcfv, uiPayloadLocation, tt);
		
	}
	else {
		printf("\tEGRESS PACKET. Dest: %s sport: %d  dport = %d packetSize = %d\n", cpDestIp, sport, dport, ulPktSize);
		WSAggAlarmProcessor(pcfv, uiPayloadLocation,tt);
		//RESTAlarmProcessor(pcfv, uiPayloadLocation, now);
		//WSProcessorVector(pcfv, uiPayloadLocation);
	}

	delete[]ucp;
}

void packet_consumer_readalarm(PCapFrameVector& pcfv) 
{
	int iCmp = 0;
	int iDestType = 0;
	unsigned int sequenceNum;
	char cpDestIp[64];
	u_short sport, dport;
	u_char* ucpPayload;
	ip_header* ih;
	tcp_header* tcpH;

	pcap_pkthdr header = pcfv.rtHeader();
	//get the packet data
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	TcpFrameInspector tcpInspector(ucp, ulPktSize);
	tcpInspector.inspectFrameNoDbg();
	sport = tcpInspector.rtSport();
	dport = tcpInspector.rtDport();
	sequenceNum = tcpInspector.rtSequenceNum();
	u_int uiPayloadLocation = tcpInspector.rtPayloadLocation();
	ih = tcpInspector.rtIpHeader();
	tcpH = tcpInspector.rtTcpHeader();
	strcpy(cpDestIp, tcpInspector.rtDestIp());
	iCmp = strcmp(cpDestIp, cpAggregatorIP);
	if (iCmp == 0)
	{
		iDestType = 1;
	}
	else {
		iCmp = strcmp(cpDestIp, cpPNCIP);
		if (iCmp == 0)
			iDestType = 2;
	}
	if (iDestType == 0) {//Stop processing the destination test failed
		/*printf("Destination test failed! cpDestIP: %s cpAggregatorIP: %s cpPNCIP %s Dest Port: %d\n",
			cpDestIp, cpAggregatorIP, cpPNCIP, dport);*/

		return;
	}
	if (iDestType == 1 && dport != usAggPort) {
		//printf("Bad packet, dest is Agg:%s, but port is: %d\n", cpAggregatorIP, dport);
		return;
	}
	if (iDestType == 2 && sport != usAggPort) {
		//printf("Bad packet, dest is PNC:%s, but port is: %d\n", cpPNCIP, dport);
		return;
	}
	//Get a timestamp
	unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	ucpPayload = (u_char*)&ucp[uiPayloadLocation];
	if (iDestType == 1)// This may be a PUT READ to the agg
	{
		printf("INGRESS PACKET. Dest: %s sport: %d  dport = %d\n",cpDestIp,sport,dport);
		AggregatorProcessorVector(pcfv, uiPayloadLocation, now);
		//AggregatorProcessor(now, ih, tcpH, ucpPayload, tcpInspector.rtIpDataLen() - uiPayloadLocation);
	}
	else {
		printf("EGRESS PACKET. Dest: %s sport: %d  dport = %d\n", cpDestIp, sport, dport);
		//RESTAlarmProcessor(pcfv, uiPayloadLocation,now);
		WSProcessorVector(pcfv, uiPayloadLocation);
	}

	delete[]ucp;
}


void pnc_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	tcp_header* tcpH;
	u_int ip_len;
	u_int uiPayloadLocation;
	u_short sport, dport;
	u_short ipDataLen;
	u_short offset;
	u_short windowSize;
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;
	u_int uiTcpHeaderSize;
	u_char* ucpPayload;
	unsigned int sequenceNum;
	unsigned int ackNum;
	
	BYTE b = 0;
	int bStandard = 0;
	int iCmp = 0;
	int iDestType = 0;
	char cpDestIp[64];
	
	std::string* strp = new std::string();
	
	(VOID)(param);
	TcpFrameInspector* tcpInspector = new TcpFrameInspector(pkt_data, header->caplen);
	tcpInspector->inspectFrameNoDbg();
	sport = tcpInspector->rtSport();
	dport = tcpInspector->rtDport();
	sequenceNum = tcpInspector->rtSequenceNum();
	ackNum = tcpInspector->rtAckNum();
	ipDataLen = tcpInspector->rtIpDataLen();
	uiTcpHeaderSize = tcpInspector->rtTcpHeaderSize();
	windowSize = tcpInspector->rtWindowSize();
	strcpy(cpDestIp, tcpInspector->rtDestIp());
	uiPayloadLocation = tcpInspector->rtPayloadLocation();
	ih = tcpInspector->rtIpHeader();
	tcpH = tcpInspector->rtTcpHeader();
	if (tcpInspector->isMFBitSet()) {
		std::cout << "MF BIT IS SET" << std::endl;
	}
	
	ip_len = (ih->ver_ihl & 0xf) * 4;
	
	iCmp = strcmp(cpDestIp, cpAggregatorIP);
	if (iCmp == 0)
	{
		iDestType = 1;
	}
	else {
		iCmp = strcmp(cpDestIp, cpPNCIP);
		if (iCmp == 0)
			iDestType = 2;
	}
	if (iDestType == 0) {//Stop processing the destination test failed
		//puts("Destination test failed!");
		return;
	}
	if (iDestType == 1 && dport != usAggPort) {
		//printf("Bad packet, dest is Agg:%s, but port is: %d\n", cpAggregatorIP, dport);
		return;
	}
	if (iDestType == 2 && dport != usPncPort) {
		//printf("Bad packet, dest is PNC:%s, but port is: %d\n", cpPNCIP,dport);
		return;
	}
	//Get a timestamp
	unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	
	ucpPayload = (u_char*)&pkt_data[uiPayloadLocation];
	if (iDestType == 1)// This may be a PUT READ to the agg
	{
		
		AggregatorProcessor(now, ih, tcpH, ucpPayload, ipDataLen - uiPayloadLocation);
	}
	else {
		if (ipDataLen <= uiPayloadLocation) {
			ipDataLen = header->caplen;
		}
		PNCProcessor(now, ih, tcpH, ucpPayload, ipDataLen - uiPayloadLocation,ipDataLen,pkt_data);
	}
}

void RESTAlarmProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp)
{
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message
		ullCntrl++;
		return;
	}
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	unsigned char* ucpPayload = &ucp[uiPayloadLocation];
	char* cpUrl = strstr((char*)ucpPayload, "<read id=");
	if (cpUrl == NULL) {
		writeBadAggPacket((char*)ucpPayload, pv->size() - uiPayloadLocation);
		ullNoId++;
		return;
	}
	//crawl up to the begining of the id
	for (int i = 0;i < 10;i++) {
		cpUrl++;
	}
	//printf("RESTAlarmProcessor: %s\n", cpUrl);
	// Get everything up to the " character
	char cpTemp[128];
	memset(&cpTemp, 0, 128);
	int cnt = 0;
	do {
		if (cpUrl[cnt] == ' ' || cpUrl[cnt] == '"')  
			break;
		cpTemp[cnt] = cpUrl[cnt];
		cnt++;
	} while (cnt < 126);
	//printf("\tRESTAlarmProcessor: the id: %s timeStamp: %lu\n",cpTemp,timeStamp);
	ReadInfo theId(cpTemp, pcfv.rtTimeStamp());
	unsigned __int64 tempTime;
	bool bFind = pAggRecMap->isThere(cpTemp, tempTime);
	if (bFind) {
		ReadInfo r(cpTemp, tempTime);
		AlarmReporter(r, theId, *tgmp);
		
		//wftd->saveFrameToDisk(frameLength, pkt_data, "Msg");
	}
	else {
		ullNoMatchId++;
		writeBadAggPacket((char*)ucpPayload, pv->size() - uiPayloadLocation);
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noMatchId");
			//printf("\tPNCProcessor: the map DID NOT find a match for %s\n",theId.getId().c_str());
		
	}
	delete[]ucp;
}

void HomeAggregatorProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, time_t timeStamp) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message
		ullCntrl++;
		return;
	}
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	unsigned char* ucpPayload = &ucp[uiPayloadLocation];
	char* cpUrl = strstr((char*)ucpPayload, "PUT /read/");
	if (cpUrl == NULL) {
		//puts("\tAggregatorProcessor: could not find PUT /read/");
		writeBadAggPacket((char*)ucpPayload, pv->size() - uiPayloadLocation);
		ullNoFindPutRead++;
		return;
	}
	//crawl up to the begining of the id
	for (int i = 0;i < 10;i++) {
		cpUrl++;
	}
	// Get everything up to the " character
	char cpTemp[128];
	memset(&cpTemp, 0, 128);
	int cnt = 0;
	do {
		if (cpUrl[cnt] == ' ' || cpUrl[cnt] == '"')
			break;
		cpTemp[cnt] = cpUrl[cnt];
		cnt++;
	} while (cnt < 126);
	//printf("\tAggregatorProcessor: the id: %s timeStamp: %lu\n",cpTemp,timeStamp);
	ReadInfo theId(cpTemp, timeStamp);
	bool bIns = pAggRecMap->insertRec(theId);
	
	if (bIns) {
		//WE SHOULD WRITE THE DATA TO DISK HERE
		std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
		writeAggReadData(cpTemp, timeStamp, now);
		ullReadCnt++;
	}
	else {
		ullReadInsertFail++;
	}
	delete[]ucp;
}

void AggregatorProcessorVector(PCapFrameVector& pcfv, u_int uiPayloadLocation, unsigned __int64 timeStamp) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message
		ullCntrl++;
		return;
	}
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	unsigned char* ucpPayload = &ucp[uiPayloadLocation];
	char* cpUrl = strstr((char*)ucpPayload,"PUT /read/");
	if (cpUrl == NULL) {
		//puts("\tAggregatorProcessor: could not find PUT /read/");
		writeBadAggPacket((char *)ucpPayload, pv->size() - uiPayloadLocation);
		ullNoFindPutRead++;
		return;
	}
	//crawl up to the begining of the id
	for (int i = 0;i < 10;i++) {
		cpUrl++;
	}
	// Get everything up to the " character
	char cpTemp[128];
	memset(&cpTemp, 0, 128);
	int cnt = 0;
	do {
		if (cpUrl[cnt] == ' ' || cpUrl[cnt] == '"')
			break;
		cpTemp[cnt] = cpUrl[cnt];
		cnt++;
	} while (cnt < 126);
	//printf("\tAggregatorProcessor: the id: %s timeStamp: %lu\n",cpTemp,timeStamp);
	ReadInfo theId(cpTemp, timeStamp);
	bool bIns = pAggRecMap->insertRec(theId);
	if (bIns) {
		ullReadCnt++;
		/*char cpOutput[128] = { '\0' };
		localtime_s
		std::tm now = localtime(&theId.getTimeStamp);
		
		sprintf_s(cpOutput, sizeof(cpOutput), "%s,%s\n", asctime(info), theId.getId());
		if (outf != NULL)
		{
			*outf << cpOutput;
			outf->flush();
		}*/
	}
	else {
		ullReadInsertFail++;
	}
	delete []ucp;
}

void WSAggAlarmProcessor(PCapFrameVector& pcfv, u_int uiPayloadLocation, time_t timeStamp) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();

	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message, not a WS message
		ullCntrl++;
		return;
	}

	if (pv->size() <= (uiPayloadLocation + 9)) {//This is a WS control message
		ullWSCntrl++;
		return;
	}

	std::string* strp = new std::string();
	AnalyzeWebsocketFrameVector awf;
	awf.AnalyzeFrame(pcfv, strp, uiPayloadLocation);
	//std::cout << "WSAggAlarmProcessor: decoded string: " << strp->c_str() << std::endl;
	int n = strp->length();
	if (n <= 0) {
		ullNoDecode++;
		
		wftd->saveFrameToDisk(pcfv, "Decode FAILED");
		return;
		
	}
	char* cpId = strstr((char*)strp->c_str(), "read id=");
	if (cpId == NULL)
	{
		ullNoId++;
		*errorf << "No Id: dataLen is: " << pcfv.rtHeader().caplen << "\n" << strp->c_str() << std::endl;
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noId");
		return;
	}
	cpId++;cpId++;cpId++;cpId++;cpId++;cpId++;cpId++;cpId++;cpId++;
	//Get everything up to the " character
	char cpTemp[64];
	memset(&cpTemp, 0, 64);
	int cnt = 0;
	do {
		if (cpId[cnt] == '"')
			break;
		cpTemp[cnt] = cpId[cnt];
		cnt++;
	} while (cnt < 62);
	std::cout << "WSAggAlarmProcessor: got ID: " << cpTemp << std::endl;
	//Is this ID in pAggRecMap?
	unsigned __int64 origTimeStamp;
	if (pAggRecMap->isThere(cpTemp,origTimeStamp)) {
		//If yes compare the two time stamps and write to a file.
		time_t diffTime = timeStamp - origTimeStamp;
		//write to a file.
		*readAlarmLatency << cpTemp << "," << diffTime << std::endl;
	}
	




}

void WSProcessorVector(PCapFrameVector& pcfv, u_int uiPayloadLocation) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message, not a WS message
		ullCntrl++;
		return;
	}

	if (pv->size() <= (uiPayloadLocation + 9)) {//This is a WS control message
		ullWSCntrl++;
		return;
	}

	std::string* strp = new std::string();
	AnalyzeWebsocketFrameVector awf;
	awf.AnalyzeFrame(pcfv, strp, uiPayloadLocation);
	//std::cout << strp->c_str() << std::endl;
	int n = strp->length();
	if (n <= 0) {
		ullNoDecode++;
		return;
	}
	char* cpId = strstr((char*)strp->c_str(), "id=");
	if (cpId == NULL)
	{
		ullNoId++;
		*errorf << "No Id: dataLen is: " << pcfv.rtHeader().caplen << "\n" << strp->c_str() << std::endl;
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noId");

		return;
	}
	cpId++;cpId++;cpId++;cpId++;
	//Get everything up to the " character
	char cpTemp[64];
	memset(&cpTemp, 0, 64);
	int cnt = 0;
	do {
		if (cpId[cnt] == '"')
			break;
		cpTemp[cnt] = cpId[cnt];
		cnt++;
	} while (cnt < 62);
	ReadInfo theId(cpTemp, pcfv.rtTimeStamp());
	unsigned __int64 tempTime;
	bool bFind = pAggRecMap->isThere(cpTemp, tempTime);
	if (bFind) {
		ReadInfo r(cpTemp, tempTime);
		PNCReporter2(r, theId, *tgmp);
		//wftd->saveFrameToDisk(frameLength, pkt_data, "Msg");
	}
	else {
		ullNoMatchId++;
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noMatchId");
			//printf("\tPNCProcessor: the map DID NOT find a match for %s\n",theId.getId().c_str());
		writeBadPacket(strp, cpTemp);
	}
	delete strp;
}

void WSAlarmProcessorPNCVector(PCapFrameVector& pcfv, u_int uiPayloadLocation) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message, not a WS message
		//std::cout << "WSAlarmProcessorPNCVector: TCP control message, returning." << std::endl;
		ullCntrl++;
		return;
	}
	if (pv->size() <= (uiPayloadLocation + 9)) {//This is a WS control message
		//std::cout << "WSAlarmProcessorPNCVector: WS control message, returning." << std::endl;
		ullWSCntrl++;
		return;
	}
	std::cout << "WSAlarmProcessorPNCVector: Analyzing packet..." << std::endl;
	unsigned long ulPktSize = pv->size();
	unsigned char* ucp = new unsigned char[ulPktSize];
	std::copy(pv->begin(), pv->end(), ucp);
	unsigned char* ucpPayload = &ucp[uiPayloadLocation];

	
	//We have a decoded string. Now its time to find the READ ID
	char* cpUrl = strstr((char*)ucpPayload, "<read");
	if (cpUrl == NULL) {
		std::cout << "WSAlarmProcessorPNCVector: could not find <read"<<std::endl;
		/*outf << "Could not find <read for: " << ucpPayload << std::endl;
		*outf << "************************************************" << std::endl << std::endl;
		outf->flush();*/
		ullNoId++;
		return;
	}
	char* cpId = strstr(cpUrl, "id=");
	if (cpId == NULL) {
		std::cout << "WSAlarmProcessorPNCVector: could not find id=" << std::endl;
		ullNoId++;
		return;
	}
	std::cout << "WSAlarmProcessorPNCVector: Found ID!..." << std::endl;
	//crawl up to the begining of the id
	for (int i = 0;i < 4;i++) {
		cpId++;
	}
	char cpTemp[128];
	memset(&cpTemp, 0, 128);
	int cnt = 0;
	do {
		if (cpId[cnt] == ' ' || cpId[cnt] == '"')
			break;
		cpTemp[cnt] = cpId[cnt];
		cnt++;
	} while (cnt < 126);
	//Ok the READ ID is in cpTemp, now we have to figure out if its been seen before.
	ReadInfo theId(cpTemp, pcfv.rtTimeStamp());
	// Check ID in pPNCRecMap
	unsigned __int64 tempTime = 0;
	bool bFind = pPNCAlarmMap->isThere(cpTemp, tempTime);
	if (bFind) {
		//printf("WSAlarmProcessorPNCVector: found a dup %s, its value will be: %d\n",cpTemp, tempTime + 1);
		ReadInfo updateObj(cpTemp, tempTime + 1);
		pPNCAlarmMap->erase(cpTemp);
		pPNCAlarmMap->insertRec(updateObj);

	}
	else {
		unsigned __int64 initTime = 0;
		ReadInfo theId(cpTemp, initTime);
		pPNCAlarmMap->insertRec(theId);
	}

	delete ucp;
}

void WSProcessorPNCVector(PCapFrameVector& pcfv, u_int uiPayloadLocation) {
	std::vector<unsigned char>* pv = pcfv.rtPktData();
	//std::cout << "WSProcessorPNCVector: called!" << std::endl;
	if (uiPayloadLocation >= pv->size() - 1) {//this is probably a TCP control message, not a WS message
		//std::cout << "WSProcessorPNCVector: TCP control message, returning." << std::endl;
		ullCntrl++;
		return;
	}

	if (pv->size() <= (uiPayloadLocation + 9)) {//This is a WS control message
		//std::cout << "WSProcessorPNCVector: WS control message, returning." << std::endl;
		ullWSCntrl++;
		return;
	}
	std::cout << "WSProcessorPNCVector: Analyzing packet..." << std::endl;
	
	std::string* strp = new std::string();
	AnalyzeWebsocketFrameVector awf;
	awf.AnalyzeFrame(pcfv, strp, uiPayloadLocation);
	//std::cout << strp->c_str() << std::endl;
	int n = strp->length();
	if (n <= 0) {
		ullNoDecode++;
		return;
	}
	char* cpId = strstr((char*)strp->c_str(), "id=");
	if (cpId == NULL)
	{
		ullNoId++;
		*errorf << "No Id: dataLen is: " << pcfv.rtHeader().caplen << "\n" << strp->c_str() << std::endl;
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noId");

		return;
	}
	cpId++;cpId++;cpId++;cpId++;
	//Get everything up to the " character
	char cpTemp[64];
	memset(&cpTemp, 0, 64);
	int cnt = 0;
	do {
		if (cpId[cnt] == '"')
			break;
		cpTemp[cnt] = cpId[cnt];
		cnt++;
	} while (cnt < 62);
	ReadInfo theId(cpTemp, pcfv.rtTimeStamp());
	// Check ID in pPNCRecMap
	unsigned __int64 tempTime = 0;
	bool bFind = pPNCRecMap->isThere(cpTemp, tempTime);
	if (bFind) {
		ReadInfo updateObj(cpTemp, tempTime + 1);
		pPNCRecMap->erase(cpTemp);
		pPNCRecMap->insertRec(updateObj);

	}
	else {
		unsigned __int64 initTime = 0;
		ReadInfo theId(cpTemp, initTime);
		pPNCRecMap->insertRec(theId);
	}

	delete strp;
}

void analyzeIPv6Frame(const unsigned char* pkt_data, int len) {
	std::cout << "****** START analyzeIPv6Frame *****" << std::endl;

	TcpFrameInspector tcpInspector(pkt_data, len);
	tcpInspector.inspectFrameNoDbg();
	int iTotal = 0;
	int iGroupCount = 0;
	unsigned char IPv6Address[45];
	memset(IPv6Address, 0, sizeof(IPv6Address));
	for (int i = 22;i < 38;i++) {
		unsigned char tmp = pkt_data[i];
		unsigned char upperNibble = tcpInspector.getMostSignificantNibble(tmp);
		unsigned char lowerNibble = tcpInspector.getLeastSignificantNibble(tmp);
		unsigned char tranUpper = tcpInspector.translateNumberToChar(upperNibble);
		unsigned char tranLower = tcpInspector.translateNumberToChar(lowerNibble);
		printf("pkt_data[%d] = %u upper nibble = %u/%c  lower nibble = %u/%c\n", i, tmp,
			upperNibble, tranUpper,
			lowerNibble, tranLower);
		IPv6Address[iTotal] = tranUpper;
		iTotal++;
		iGroupCount++;
		IPv6Address[iTotal] = tranLower;
		iTotal++;
		iGroupCount++;
		if (iGroupCount >= 3) {
			IPv6Address[iTotal] = ':';
			iTotal++;
			iGroupCount = 0;
		}
		
	}
	std::cout << "Address: %s\n" << IPv6Address << std::endl;
		
	
	std::cout << "****** END analyzeIPv6Frame *****" << std::endl;
}

void analyzeWebSocketFrame(const unsigned char *pkt_data, int len) {
	TcpFrameInspector* tcpInspector = new TcpFrameInspector(pkt_data,len);
	tcpInspector->inspectFrame();
	
	u_int uiPayloadLocation;
	u_short ipDataLen;
	u_int uiTcpHeaderSize;
	std::cout << "***** analyzeWebSocketFrame *****" << std::endl;
	ipDataLen = tcpInspector->rtIpDataLen();
	uiPayloadLocation = tcpInspector->rtPayloadLocation();
	std::cout << "ipDataLen = " << ipDataLen << std::endl;
	if ((ipDataLen + 14) > uiPayloadLocation) {//There is a WS payload
		std::string* strp = new std::string();
		AnalyzeWebSocketFrame* awf = new AnalyzeWebSocketFrame((unsigned char *)&pkt_data[uiPayloadLocation], len - uiPayloadLocation);
		awf->checkFinBit();
		awf->checkOpCode();
		awf->AnalyzeFrame(strp);
		awf->checkMask();
		awf->checkPayloadLength();
		awf->checkMaskingKeys();
		awf->showDecodedPayload();
		awf->AnalyzeFrame(strp);
		if (tgmp->isMessageGarbled(*strp)) {
			std::cout << "THE MESSAGE IS GARBLED!" << std::endl;
		}
		else {
			std::cout << "THE MESSAGE IS NOT GARBLED." << std::endl;
		}
		
		delete strp;
		delete awf;
	}
	std::cout << "***** END analyzeWebSocketFrame *****" << std::endl;
	std::cout << std::endl << std::endl;
	delete tcpInspector;
}

void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	tcp_header* tcpH;
	u_int ip_len;
	u_int uiPayloadLocation;
	u_short sport, dport;
	u_short ipDataLen;
	u_short offset;
	u_short windowSize;
	u_char* leftOffSet;
	u_char offsetShifted, ucOffset;
	u_int uiTcpHeaderSize;
	u_char* ucpPayload;
	unsigned int sequenceNum;
	unsigned int ackNum;
	
	BYTE b = 0;
	int bStandard = 0;
	std::string* strp = new std::string();
	/*
	 * unused parameter
	 */
	(VOID)(param);
	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	/* retireve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcpH = (tcp_header*)((u_char*)ih + ip_len);

	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);
	ipDataLen = ntohs(ih->tlen);
	offset = tcpH->offset_res_control;
	leftOffSet = (u_char*)&tcpH->offset_res_control;
	windowSize = ntohs(tcpH->window_size);
	ucOffset = *leftOffSet;
	offsetShifted = ucOffset >> 4; //shift right to move the bits where care about to the begining.
	uiTcpHeaderSize = offsetShifted * 4;


	/* print ip addresses and udp ports */
	printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d sequence: %u ack: %u ip len: %u window size: %u\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport, sequenceNum, ackNum, ipDataLen, windowSize);
	/*printf("\toffset: %d\t", offset);
	printBits(sizeof(offset), &offset);*/
	printf("\toffsetShifted %u\t", offsetShifted);
	printBits(sizeof(char), &offset);
	uiPayloadLocation = 14 + ip_len + uiTcpHeaderSize;
	printf("\tMAC: 14 IP Header is: %u TCP Header is: %u Total: %u\n", ip_len, uiTcpHeaderSize, (unsigned)uiPayloadLocation);
	ucpPayload = (u_char*)&pkt_data[uiPayloadLocation];
	if (ipDataLen > 256)
	{
		showPayloadData(ucpPayload, 5);
		AnalyzeWebSocketFrame* awf = new AnalyzeWebSocketFrame(ucpPayload, ipDataLen - uiPayloadLocation);
		awf->AnalyzeFrame(strp);

		delete awf;
	}

	
}

void AggregatorProcessor(unsigned __int64 timeStamp, ip_header* ih, tcp_header* tcpH, u_char* ucpPayload,
	u_short dataLen)
{
	char* cp = (char *)ucpPayload;
	
	char *cpUrl = strstr((char *)cp,"PUT /read/");
	if (cpUrl == NULL) {
		//puts("\tAggregatorProcessor: could not find PUT /read/");
		//writeBadAggPacket(cp, dataLen);
		ullNoFindPutRead++;
		return;
	}
	//crawl up to the begining of the id
	for (int i = 0;i < 10;i++) {
		cpUrl++;
	}
	// Get everything up to the " character
	char cpTemp[128];
	memset(&cpTemp, 0, 128);
	int cnt = 0;
	do {
		if (cpUrl[cnt] == ' ')
			break;
		cpTemp[cnt] = cpUrl[cnt];
		cnt++;
	} while (cnt < 126);
	//printf("\tAggregatorProcessor: the id: %s timeStamp: %lu\n",cpTemp,timeStamp);
	ReadInfo theId(cpTemp, timeStamp);
	bool bIns = pAggRecMap->insertRec(theId);
	if (bIns) {
		ullReadCnt++;
	}
	else {
		ullReadInsertFail++;
	}
	/*
	std::pair<std::map<std::string, ReadInfo>::iterator,bool> result = aggMap.insert(std::make_pair<std::string, ReadInfo>(std::string(theId.getId()), ReadInfo(theId.getId(), theId.getTimeStamp())));
	if (result.second) {
		ullReadCnt++;
	}
	else {
		ullReadInsertFail++;
	}*/
	//writeAggInsert(theId);
}


void PNCProcessor(unsigned long long timeStamp, ip_header* ih, tcp_header* tcpH, u_char* ucpPayload,
	u_short dataLen, u_short frameLength, const u_char* pkt_data)
{
	
	
	if (dataLen <= 54)// this is probably a control message, not a true message
	{
		//printf("\tPNCProcessor: data length is less then 256:%d\n", dataLen);
		//wftd->saveFrameToDisk(frameLength, pkt_data,"ctrlMsg");
		ullCntrl++;
		return;
	}
	if (dataLen <= 63) {//this is proabably a WS control message
		ullWSCntrl++;
		return;
	}
	//printf("\tPNCProcessor: going to process data with length:%d\n", dataLen);
	
	std::string* strp = new std::string();
	AnalyzeWebSocketFrame* awf = new AnalyzeWebSocketFrame(ucpPayload,frameLength);
	awf->AnalyzeFrame(strp);
	int n = strp->length();
	if (n <= 0) {
		ullNoDecode++;
		*errorf << "Unmasking failed for: " << strp->c_str() << std::endl;
		//wftd->saveFrameToDisk(frameLength, pkt_data, "unmaskingFailed");
		return;
	}
	char* cpId = strstr((char *)strp->c_str(), "id=");
	if (cpId == NULL)
	{
		//puts("\tPNCProcessor: could not find id=");
		//wftd->saveFrameToDisk(frameLength, pkt_data,"noFindId");
		//writeBadPacket(strp, "PNCProcessor: could not find 'id='");
		ullNoId++;
		//tgmp->isMessageGarbled(*strp);
		return;
	}
	//crawl up to the begining of the id
	cpId++;cpId++;cpId++;cpId++;

	//Get everything up to the " character
	char cpTemp[64];
	memset(&cpTemp, 0, 64);
	int cnt = 0;
	do {
		if (cpId[cnt] == '"')
			break;
		cpTemp[cnt] = cpId[cnt];
		cnt++;
	} while (cnt < 62);
	//printf("\tPNCProcessor: Id: %s Timestamp:%lu\n", cpTemp,timeStamp);
	
	ReadInfo theId(cpTemp, timeStamp);
	unsigned __int64 tempTime;
	bool bFind = pAggRecMap->isThere(cpTemp,tempTime);
	if (bFind) {
		ReadInfo r(cpTemp, tempTime);
		PNCReporter2(r, theId, *tgmp);
		//wftd->saveFrameToDisk(frameLength, pkt_data, "Msg");
	}
	else {
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noMatchId");
			//printf("\tPNCProcessor: the map DID NOT find a match for %s\n",theId.getId().c_str());
		ullNoMatchId++;
		writeBadPacket(strp, cpTemp);
	}
	/*
	
	std::map<std::string, ReadInfo>::iterator aggIt;
	aggIt = aggMap.find(theId.getId());
	if (aggIt != aggMap.end()) {
		ReadInfo r = aggIt->second;
		//printf("\tPNCProcessor: the map found a match: %s\n", r.getId().c_str());
		
		PNCReporter2(r, theId,*tgmp);
		//wftd->saveFrameToDisk(frameLength, pkt_data, "Msg");
		
	}
	else {
		//wftd->saveFrameToDisk(frameLength, pkt_data, "noMatchId");
		//printf("\tPNCProcessor: the map DID NOT find a match for %s\n",theId.getId().c_str());
		writeBadPacket(strp,cpTemp);
	}*/
	

	delete awf;
	delete strp;
}

void AlarmReporter(ReadInfo read, ReadInfo alrm, TrackGarbledMessages& tgm) {
	unsigned long long ullCurrent;
	char cpOutput[128] = { '\0' };
	ullAlarmCnt++;
	ullCurrent = alrm.getTimeStamp() - read.getTimeStamp();
	ullTotal = ullTotal + ullCurrent;
	iSampleCount++;
	bool bErase = pAggRecMap->erase(alrm.getId());
	if (!bErase) {
		printf("%s was not erased.\n", alrm.getId().c_str());
	}
	
	if (ullCurrent < ullAlrmLowTarget) {
		iAlrmLowTargetCnt++;
		printf("AlarmReporter: id: %s Delay: %lu LOW TARGET\n", alrm.getId().c_str(), ullCurrent);
		
	}
	else if (ullCurrent < ullAlrmMidTarget) {
		iAlrmMidTargetCnt++;
		printf("AlarmReporter: id: %s Delay: %lu MID TARGET, READ TIME: %lu\n", alrm.getId().c_str(), ullCurrent, read.getTimeStamp());
	}
	else if (ullCurrent < ullAlrmHighTarget) {
		iAlrmHighTargetCnt++;
		printf("AlarmReporter: id: %s Delay: %lu HIGH TARGET, READ TIME: %lu\n", alrm.getId().c_str(), ullCurrent, read.getTimeStamp());
	} 
	else if (ullCurrent > ullAlrmHighTarget) {
		printf("AlarmReporter: id: %s Delay: %lu OVER HIGH TARGET, READ TIME: %lu\n", alrm.getId().c_str(), ullCurrent, read.getTimeStamp());
	}
	sprintf_s(cpOutput, sizeof(cpOutput), "%s,%lu,%lu,%lu\n", alrm.getId().c_str(),ullCurrent, alrm.getTimeStamp(), read.getTimeStamp());
	

	if (outf != NULL)
	{
		*outf << cpOutput;
		outf->flush();
	}
}

void PNCReporter2(ReadInfo read, ReadInfo pnc, TrackGarbledMessages& tgm) {
	unsigned long long ullCurrent;
	
	ullPNCCnt++;
	ullCurrent = pnc.getTimeStamp() - read.getTimeStamp();
	ullTotal = ullTotal + ullCurrent;
	iSampleCount++;
	bool bErase = pAggRecMap->erase(pnc.getId());
	if (!bErase) {
		printf("%s was not erased.", pnc.getId().c_str());
	}
	
	
	if (ullCurrent < ullLowTarget) {
		iLowTargetCnt++;
	}
	else if (ullCurrent < ullMidTarget) {
		iMidTargetCnt++;
		
	}
	else if (ullCurrent < ullHighTarget) {
		iHighTargetCnt++;		
	}
	
	if (iSampleCount > 1000) {
		char cpOutput[128] = { '\0' };
		unsigned long long ulCntDiff = ullReadCnt - ullPNCCnt;

		unsigned long long ullAvg = ullTotal / iSampleCount;

		/*printf("TimeDifference avg over last 1000: %lu low: %d mid: %d high: %d Over: %d\n",
			(unsigned long)ullAvg,iLowTargetCnt,iMidTargetCnt,iHighTargetCnt,iSampleCount - (iLowTargetCnt + iMidTargetCnt + iHighTargetCnt));*/
		sprintf_s(cpOutput, sizeof(cpOutput), "%lu,%d,%d,%d,%d,%lu,%lu,%lu,%lu,%d,%lu\n",
			(unsigned long)ullAvg, iLowTargetCnt, iMidTargetCnt, iHighTargetCnt,
			iSampleCount - (iLowTargetCnt + iMidTargetCnt + iHighTargetCnt), ulCntDiff, 
			ullReadCnt, ullPNCCnt, ullReadInsertFail, iSampleCount,tgm.rtCnt());
		std::cout << cpOutput;
		
		//printf("\tItems in map: before: %lu after: %lu\n", ulBeforeSize,aggMap.size());
		if (outf != NULL)
		{
			*outf << cpOutput;
			outf->flush();
		}

		iLowTargetCnt = 0;
		iMidTargetCnt = 0;
		iHighTargetCnt = 0;
		iSampleCount = 0;
		ullTotal = 0;
	}
}

void PNCReporter(ReadInfo read, ReadInfo pnc)
{
	unsigned long long ullCurrent;
	
	ullPNCCnt++;
	if (iSampleCount < 1000) {
		ullCurrent = pnc.getTimeStamp() - read.getTimeStamp();
		ullTotal = ullTotal + ullCurrent;
		iSampleCount++;
		bool bErase = pAggRecMap->erase(pnc.getId());
		if (!bErase) {
			printf("%s was not erased.", pnc.getId().c_str());
		}
		/*
		unsigned long ulBefore = aggMap.size();
		int iErase = aggMap.erase(pnc.getId());
		if (iErase < 1) {
			printf("%s was not erased.", pnc.getId().c_str());
		}
		unsigned long ulAfter = aggMap.size();*/
		//writeMapSize(ulBefore,ulAfter);
		if (ullCurrent < ullLowTarget) {
			iLowTargetCnt++;
			return;
		}
		if (ullCurrent < ullMidTarget) {
			iMidTargetCnt++;
			return;
		}
		if (ullCurrent < ullHighTarget) {
			iHighTargetCnt++;
			return;
		}
		
	}
	else {
		char cpOutput[128] = { '\0' };
		unsigned long long ulCntDiff = ullReadCnt - ullPNCCnt;

		unsigned long long ullAvg = ullTotal / iSampleCount;
		
		/*printf("TimeDifference avg over last 1000: %lu low: %d mid: %d high: %d Over: %d\n", 
			(unsigned long)ullAvg,iLowTargetCnt,iMidTargetCnt,iHighTargetCnt,iSampleCount - (iLowTargetCnt + iMidTargetCnt + iHighTargetCnt));*/
		sprintf_s(cpOutput, sizeof(cpOutput), "%lu,%d,%d,%d,%d,%lu,%lu,%lu,%lu,%d\n", 
			(unsigned long)ullAvg, iLowTargetCnt, iMidTargetCnt, iHighTargetCnt, 
			iSampleCount - (iLowTargetCnt + iMidTargetCnt + iHighTargetCnt),ulCntDiff,ullReadCnt,ullPNCCnt,ullReadInsertFail,iSampleCount);
		std::cout << cpOutput;
		bool bErase = pAggRecMap->erase(pnc.getId());
		if (!bErase) {
			printf("%s was not erased.", pnc.getId().c_str());
		}
		/*
		unsigned long ulBeforeSize = aggMap.size();

		int iErase = aggMap.erase(pnc.getId());
		if (iErase < 1) {
			printf("%s was not erased.", pnc.getId().c_str());
		}*/
		
		//printf("\tItems in map: before: %lu after: %lu\n", ulBeforeSize,aggMap.size());
		if (outf != NULL)
		{
			*outf << cpOutput;
			outf->flush();
		}

		iLowTargetCnt = 0;
		iMidTargetCnt = 0;
		iHighTargetCnt = 0;
		iSampleCount = 0;
		ullTotal = 0;
	}
	//printf("TimeDifference is: %lu milliseconds\n", (unsigned long)pnc.getTimeStamp() - read.getTimeStamp());
}


void showPayloadData(u_char* ucp, int num)
{
	printf("\tPayload: ");
	for (int i = 0;i < num;i++)
	{
		printf("0x%x ", ucp[i]);
	}
	printf("\n");
}

//assumes little endian
void printBits(size_t const size, void const* const ptr)
{
	unsigned char* b = (unsigned char*)ptr;
	unsigned char byte;
	int i, j;

	for (i = size - 1;i >= 0;i--)
	{
		for (j = 7;j >= 0;j--)
		{
			byte = (b[i] >> j) & 1;
			printf("%u", byte);
		}
	}
	puts("");
}

int isStandard(unsigned char c)
{
	if (c < 240)
	{
		return 1;
	}
	return 0;
}

void writeBadPacket(std::string* strp,char *cp) {
	*errorf << "cp=" << cp << std::endl;
	*errorf << *strp << std::endl;
	*errorf << "*****************" << std::endl;
	
	errorf->flush();
}

void writeMapSize(unsigned long ulBefore, unsigned long ulAfter) {
	*errorf << "Before: " << ulBefore << " After: " << ulAfter << std::endl;
}

void writeBadAggPacket(char *cp,int dataLen) {
	
	if (dataLen > 40) {
		char* cpLog = cp;
		for (int i = 0; i < dataLen;i++) {
			*aggErrorf << cpLog[i];
			
		}
		*aggErrorf<<std::endl << "****************************************************************" << std::endl;
		*aggErrorf << std::endl << std::endl;
		aggErrorf->flush();
		
	}
}

void writeAggInsert(ReadInfo ri) {
	*aggErrorf << ri.getId() << "\t" << ri.getTimeStamp() << std::endl;
	aggErrorf->flush();
}

void writePncCheckError(u_short ipDataLen, u_int uiPayloadLocation, u_int ip_len, u_int uiTcpHeaderSize,unsigned int uiHeaderLen,
	unsigned int uiCapLen,unsigned char c) {
	char* cp;
	BYTE b = (BYTE)c;

	WSFirstByteDecoder wsfbd(b);
	if (wsfbd.finalFragment()) {
		cp = "Final Fragment";
	}
	else {
		cp = "NF Fragment";
	}
	std::string s;
	wsfbd.getOpCode(s);
	
	*pncErrorf << "ipDataLen: " << ipDataLen << " uiPayloadLocation: " << uiPayloadLocation << " ip_len: " << ip_len <<
		" uiTcpHeaderSize: " << uiTcpHeaderSize << " header Length: " << uiHeaderLen << " uiCapLen: " << uiCapLen << " " << 
		cp << " " << s.c_str() << std::endl;
	pncErrorf->flush();
}

void AlarmEndOfRunReport() {

	double lowPercent = (double)iAlrmLowTargetCnt / ullAlarmCnt;
	double midPercent = ((double)iAlrmLowTargetCnt + (double)iAlrmMidTargetCnt) / ullAlarmCnt;
	double highPercent = ((double)iAlrmLowTargetCnt + (double)iAlrmMidTargetCnt + (double)iAlrmHighTargetCnt) / ullAlarmCnt;
	unsigned long long numOver = ullAlarmCnt - (iAlrmLowTargetCnt + iAlrmMidTargetCnt + iAlrmHighTargetCnt);
	
	std::cout << "Alarm End Of Run Report: \n\tLow Target: " <<100 * lowPercent << "\n\tMid Target: " <<100 * midPercent << "\n\t" << "High Target: "
		<< 100 * highPercent << std::endl;
	if (numOver > 0) {
		std::cout <<"\t"<< numOver << " Alarms were over the high threshold." << std::endl;
	}
	
}


BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {

	switch (fdwCtrlType) {
	case CTRL_C_EVENT:
		std::cout << "CTRL-C Caught..." << std::endl;
		if (iClassType == 5) {//We are using pncdupprocessor
			std::cout << "Calculating Duplicates: " << std::endl;

			pPNCRecMap->calculateDups();
			pPNCRecMap->writeDupsToFile();
			std::cout << "Number of distinct READS: " << pPNCRecMap->rtRawDistinctReadIds() << std::endl;
			std::cout << "Number of duplicate READS: " << pPNCRecMap->rtRawDuplicateReads() << std::endl;
			std::cout << "Percentage of READS duplicated: " << pPNCRecMap->rtPercentReadsDuplicated() << std::endl;	
			exit(1);
			break;
		}
		if (iClassType == 6) {
			pPNCRecMap->calculateDups();
			pPNCRecMap->writeDupsToFile();
			pPNCAlarmMap->calculateDups();
			pPNCAlarmMap->writeDupsToFile();
			std::cout << "Number of distinct READS: " << pPNCRecMap->rtRawDistinctReadIds() << std::endl;
			std::cout << "Number of duplicate READS: " << pPNCRecMap->rtRawDuplicateReads() << std::endl;
			std::cout << "Percentage of READS duplicated: " << pPNCRecMap->rtPercentReadsDuplicated() << std::endl;
			std::cout << "Number of distinct ALARMS: " << pPNCAlarmMap->rtRawDistinctReadIds() << std::endl;
			std::cout << "Number of duplicate ALARMS: " << pPNCAlarmMap->rtRawDuplicateReads() << std::endl;
			std::cout << "Percentage of ALARMS duplicated:  " << pPNCAlarmMap->rtPercentReadsDuplicated() << std::endl;
			exit(1);
			break;
		}
		std::cout << "Size of READ Queue: " << pAggRecMap->getSize() << std::endl;
		std::cout << "Total Number of READS added: " << ullReadCnt << std::endl;
		std::cout << "Total Number of Messages trapped going to the PNC: " << ullPNCCnt << std::endl;
		std::cout << "Total Number of Messages trapped as Alarms: " << ullAlarmCnt << std::endl;
		std::cout << "\tAlarms Low Target: " << iAlrmLowTargetCnt << std::endl;
		std::cout << "\tAlarms Mid Target: " << iAlrmMidTargetCnt << std::endl;
		std::cout << "\tAlarms High Target: " << iAlrmHighTargetCnt << std::endl;
		AlarmEndOfRunReport();
		pAggRecMap->saveMapToDisk(queueContents);
		std::cout << "Num of WS Control messages: " << ullWSCntrl << std::endl;
		std::cout << "Number of Control Messages: " << ullCntrl << std::endl;
		std::cout << "Number of failed decode: " << ullNoDecode << std::endl;
		std::cout << "Number of messages with no ID: " << ullNoId << std::endl;
		std::cout << "Number of WS messages we could not match to READ: " << ullNoMatchId << std::endl;
		std::cout << "Number of incoming messages with no PUT READ: " << ullNoFindPutRead << std::endl;
		exit(1);
		break;
	case CTRL_CLOSE_EVENT:
		std::cout << "Ctrl-Close event" << std::endl;
		
		break;
	case CTRL_BREAK_EVENT:
		std::cout << "Ctrl-Break event" << std::endl;
		std::cout << "Total Number of READS added: " << ullReadCnt << std::endl;
		std::cout << "Total Number of Messages trapped going to the PNC: " << ullPNCCnt << std::endl;
		std::cout << "Total number in pFrameQueueVector: " << pframeQueueVector->getSize() << std::endl;
		break;
	case CTRL_LOGOFF_EVENT:
		std::cout << "Ctrl-Logoff event" << std::endl;
		break;
	case CTRL_SHUTDOWN_EVENT:
		std::cout << "Ctrl-Shutdown event" << std::endl;
		break;
	}
	
	return TRUE;
}