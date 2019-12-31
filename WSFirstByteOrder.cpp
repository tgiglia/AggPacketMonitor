#include "pch.h"
#include "WSFirstByteDecoder.h"

bool WSFirstByteDecoder::finalFragment() {
	CBitMasking mask(b);
	if (mask.CheckBit(CBitMasking::Bit8)) {		
		return true;
	}
	return false;
}

void WSFirstByteDecoder::getOpCode(std::string& s) {
	CBitMasking mask(b);
	//mask off the 
	mask.ClearBit(CBitMasking::Bit8);mask.ClearBit(CBitMasking::Bit7);mask.ClearBit(CBitMasking::Bit6);mask.ClearBit(CBitMasking::Bit5);
	BYTE cleared = mask.rtMask();
	switch (cleared)
	{
	case 0: s.append("Continuation Frame.");
		break;
	case 1: s.append("Text Frame.");
		break;
	case 2: s.append("Binary Frame.");
		break;
	case 3: s.append("Reserved Non-Control Frame.");
		break;
	case 4: s.append("Reserved Non-Control Frame.");
		break;
	case 5: s.append("Reserved Non-Control Frame.");
		break;
	case 6: s.append("Reserved Non-Control Frame.");
		break;
	case 7: s.append("Reserved Non-Control Frame.");
		break;
	case 8: s.append("Connection Close.");
		break;
	case 9: s.append("Ping Frame.");
		break;
	case 10: s.append("Pong Frame.");
		break;
	default: s.append("Further Control Frame.");
	}


}

void WSFirstByteDecoder::showByte() {
	CBitMasking mask(b);
	mask.Display();
}