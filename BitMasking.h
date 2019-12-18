#pragma once
#include<wtypes.h>

class CBitMasking
{

public:
	CBitMasking(BYTE& mask);
	enum Bits
	{
		Bit1 = 0,
		Bit2 = 1,
		Bit3 = 2,
		Bit4 = 3,
		Bit5 = 4,
		Bit6 = 5,
		Bit7 = 6,
		Bit8 = 7
	};

	void SetBit(Bits bits);
	void ClearBit(Bits bits);
	void ToggleBit(Bits bits);
	bool CheckBit(Bits bits);
	void Display();
	BYTE rtMask() { return m_Mask; }
private:
	BYTE m_Mask;
};
