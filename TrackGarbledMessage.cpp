#include "pch.h"
#include "TrackGarbledMessages.h"


bool TrackGarbledMessages::isMessageGarbled(std::string& s) {
	unsigned int uiPrintable=0;
	unsigned int uiNotPrintable=0;

	for (char const& c : s) {
		if (c > 31 && c < 127) {
			uiPrintable++;
		}
		else {
			uiNotPrintable++;
		}
		if (uiPrintable == 0) {
			ullCnt++;
			return true;
		}
		if (uiNotPrintable == 0) {
			return false;
		}
		float fNotPrintableRatio = (float)uiNotPrintable / (float) uiPrintable;
		if (fNotPrintableRatio > fPercentageThreshold) {
			ullCnt++;
			return true;
		}
	}
	return false;
}