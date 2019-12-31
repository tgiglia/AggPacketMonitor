#include "pch.h"
#include <pcap.h>
#include <chrono>
#include <iostream>
#include <map>
#include <iterator>
#include <fstream>
#include "AnaylyzeWebsocketFrame.h"
#include "concurrent_queue.h"
#include "WSFirstByteDecoder.h"
#include "WriteFrameToDisk.h"
#include "Frames.h"


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


/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

//TCP Header
typedef struct tcp_header
{
	u_short sport;
	u_short dport;
	unsigned int sequence_number;
	unsigned int ack_number;
	u_short offset_res_control;//data offset=4bits,reserved=3bits,control flags=9bits
	u_short window_size;
	u_short checksum;
	u_short urgent_pointer;
}tcp_header;

typedef struct idType
{
	char cpId[64];
}idType;



typedef struct reportRec
{
	char cpId[64];
	unsigned __int64 readTimeStamp;
	unsigned __int64 pncTimeStamp;
}reportRec;

void tcp_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void pnc_packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
void printBits(size_t const size, void const* const ptr);
int isStandard(unsigned char c);
void showPayloadData(u_char* ucp, int num);
void AggregatorProcessor(unsigned __int64 timeStamp, ip_header *ih, tcp_header *tcpH, u_char* ucpPayload, 
	u_short dataLen);
void PNCProcessor(unsigned __int64 timeStamp, ip_header* ih, tcp_header* tcpH, u_char* ucpPayload,
	u_short dataLen,u_short frameLength);
void PNCReporter(ReadInfo read, ReadInfo pnc);
void PNCReporter2(ReadInfo read, ReadInfo pnc);
void writeBadPacket(std::string* strp,char* cp);
void writeBadAggPacket(char* cp, int dataLen);
void writeMapSize(unsigned long ulBefore, unsigned long ulAfter);
void writeAggInsert(ReadInfo ri);
void writePncCheckError(u_short ipDataLen, u_int uiPayloadLocation, u_int ip_len, u_int uiTcpHeaderSize, unsigned int uiHeaderLen,
	unsigned int uiCapLen,unsigned char c);
void analyzeWebSocketFrame(const unsigned char pkt_data, int len);

std::map<ReadInfo,int> readsMap;
std::map<std::string, ReadInfo> aggMap;
char cpAggregatorIP[64];
char cpPNCIP[64];
u_short usAggPort = 8099;
u_short usPncPort = 8100;
//concurrent_queue<reportRec>* reportQueue;
unsigned long long ullTotal = 0;
unsigned long long ullLowTarget = 1500;
unsigned long long ullMidTarget = 2250;
unsigned long long ullHighTarget = 3750;
unsigned long long ullReadCnt = 0;
unsigned long long ullReadInsertFail = 0;
unsigned long long ullPNCCnt = 0;

int iLowTargetCnt = 0;
int iMidTargetCnt = 0;
int iHighTargetCnt = 0;
int iSampleCount;

std::ofstream* outf;
std::ofstream* errorf;
std::ofstream* aggErrorf;
std::ofstream* pncErrorf;

WriteFrameToDisk* wftd;



int main(array<System::String ^> ^args)
{
	std::cout << "AggPacketMonitor started!" << std::endl;
	runNpcap();
	std::cout << "AggPacketMonitor terminating." << std::endl;
    return 0;
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
	char packet_filter[] = "ip and tcp and host 10.24.2.3 and \(dst port 8099 or dst port 8100\)"; 
	//char packet_filter[] = "ip and tcp and host 10.24.2.3 and dst port 8099";
	struct bpf_program fcode;
	unsigned short us = 5;
	
	strcpy(cpAggregatorIP, "10.24.2.3");
	strcpy(cpPNCIP, "10.24.2.181");

	
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
		1000,			// read timeout
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
	printf("packet_filter = %s", packet_filter);

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
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
	pcap_loop(adhandle, 0, pnc_packet_handler, NULL);

	delete outf;
	delete errorf;
	delete aggErrorf;
	delete pncErrorf;
	delete wftd;
	return 0;
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
	/*printf("%d.%d.%d.%d.%d -> %d.%d.%d.%d.%d sequence: %u ack: %u ip len: %u window size: %u\n",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport, sequenceNum, ackNum, ipDataLen, windowSize);*/
	sprintf(cpDestIp, "%d.%d.%d.%d", ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4);
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
		puts("Destination test failed!");
		return;
	}
	if (iDestType == 1 && dport != usAggPort) {
		printf("Bad packet, dest is Agg:%s, but port is: %d\n", cpAggregatorIP, dport);
		return;
	}
	if (iDestType == 2 && dport != usPncPort) {
		printf("Bad packet, dest is PNC:%s, but port is: %d\n", cpPNCIP,dport);
		return;
	}
	//Get a timestamp
	unsigned __int64 now = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	//we got a valid packet lets parse the tcp header and get the start of the payload
	//printf("\toffsetShifted %u\t", offsetShifted);
	//printBits(sizeof(char), &offset);
	uiPayloadLocation = 14 + ip_len + uiTcpHeaderSize;
	//printf("\tMAC: 14 IP Header is: %u TCP Header is: %u Total: %u\n", ip_len, uiTcpHeaderSize, (unsigned)uiPayloadLocation);
	ucpPayload = (u_char*)&pkt_data[uiPayloadLocation];
	if (iDestType == 1)// This may be a PUT READ to the agg
	{
		//printf("\t%s:%d is a Aggregator message\n", cpDestIp, dport);
		AggregatorProcessor(now, ih, tcpH, ucpPayload, ipDataLen - uiPayloadLocation);
	}
	else {
		if (ipDataLen <= uiPayloadLocation) {
			//puts("ipDataLen is less than uiPayloadLocation - not processing this packet.");
			ipDataLen = header->caplen;
		}
		writePncCheckError(ipDataLen, uiPayloadLocation, ip_len, uiTcpHeaderSize, header->len, header->caplen, ucpPayload[0]);
		PNCProcessor(now, ih, tcpH, ucpPayload, ipDataLen - uiPayloadLocation,ipDataLen);
	}
}

void analyzeWebSocketFrame(const unsigned char pkt_data, int len) {
	ip_header* ih;
	tcp_header* tcpH;
	u_int ip_len;
	u_short sport, dport;
	u_short ipDataLen;
	unsigned int sequenceNum;
	unsigned int ackNum;
	u_short windowSize;

	/* retrieve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header
	/* retireve the position of the tcp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	tcpH = (tcp_header*)((u_char*)ih + ip_len);

	sport = ntohs(tcpH->sport);
	dport = ntohs(tcpH->dport);
	windowSize = ntohs(tcpH->window_size);
	sequenceNum = ntohl(tcpH->sequence_number);
	ackNum = ntohl(tcpH->ack_number);
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
	std::pair<std::map<std::string, ReadInfo>::iterator,bool> result = aggMap.insert(std::make_pair<std::string, ReadInfo>(std::string(theId.getId()), ReadInfo(theId.getId(), theId.getTimeStamp())));
	if (result.second) {
		ullReadCnt++;
	}
	else {
		ullReadInsertFail++;
	}
	//writeAggInsert(theId);
}


void PNCProcessor(unsigned long long timeStamp, ip_header* ih, tcp_header* tcpH, u_char* ucpPayload,
	u_short dataLen, u_short frameLength)
{
	
	
	if (dataLen <= 54)// this is probably a control message, not a true message
	{
		//printf("\tPNCProcessor: data length is less then 256:%d\n", dataLen);
		wftd->saveFrameToDisk(frameLength, ucpPayload,"ctrlMsg");
		return;
	}
	//printf("\tPNCProcessor: going to process data with length:%d\n", dataLen);
	
	std::string* strp = new std::string();
	AnalyzeWebSocketFrame* awf = new AnalyzeWebSocketFrame(ucpPayload,dataLen);
	awf->AnalyzeFrame(strp);
	int n = strp->length();
	if (n <= 0) {
		*errorf << "Unmasking failed for: " << strp->c_str() << std::endl;
		return;
	}
	char* cpId = strstr((char *)strp->c_str(), "id=");
	if (cpId == NULL)
	{
		//puts("\tPNCProcessor: could not find id=");
		wftd->saveFrameToDisk(frameLength, ucpPayload,"noFindId");
		writeBadPacket(strp, "PNCProcessor: could not find 'id='");
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
	ReadInfo theId(cpTemp,timeStamp);
	
	std::map<std::string, ReadInfo>::iterator aggIt;
	aggIt = aggMap.find(theId.getId());
	if (aggIt != aggMap.end()) {
		ReadInfo r = aggIt->second;
		//printf("\tPNCProcessor: the map found a match: %s\n", r.getId().c_str());
		PNCReporter2(r, theId);
		
		
	}
	else {
		wftd->saveFrameToDisk(frameLength, ucpPayload, "noMatchId");
		printf("\tPNCProcessor: the map DID NOT find a match for %s\n",theId.getId().c_str());
		writeBadPacket(strp,cpTemp);
	}
	

	delete awf;
	delete strp;
}

void PNCReporter2(ReadInfo read, ReadInfo pnc) {
	unsigned long long ullCurrent;

	ullPNCCnt++;
	ullCurrent = pnc.getTimeStamp() - read.getTimeStamp();
	ullTotal = ullTotal + ullCurrent;
	iSampleCount++;
	unsigned long ulBefore = aggMap.size();
	int iErase = aggMap.erase(pnc.getId());
	if (iErase < 1) {
		printf("%s was not erased.", pnc.getId().c_str());
	}
	unsigned long ulAfter = aggMap.size();
	//writeMapSize(ulBefore,ulAfter);
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
		sprintf_s(cpOutput, sizeof(cpOutput), "%lu,%d,%d,%d,%d,%lu,%lu,%lu,%lu,%d\n",
			(unsigned long)ullAvg, iLowTargetCnt, iMidTargetCnt, iHighTargetCnt,
			iSampleCount - (iLowTargetCnt + iMidTargetCnt + iHighTargetCnt), ulCntDiff, ullReadCnt, ullPNCCnt, ullReadInsertFail, iSampleCount);
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
		unsigned long ulBefore = aggMap.size();
		int iErase = aggMap.erase(pnc.getId());
		if (iErase < 1) {
			printf("%s was not erased.", pnc.getId().c_str());
		}
		unsigned long ulAfter = aggMap.size();
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
		unsigned long ulBeforeSize = aggMap.size();

		int iErase = aggMap.erase(pnc.getId());
		if (iErase < 1) {
			printf("%s was not erased.", pnc.getId().c_str());
		}
		
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
			*aggErrorf << cpLog[i] << " ";
			
		}
		*aggErrorf << "****" << std::endl;
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