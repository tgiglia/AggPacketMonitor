#include "pch.h"
#include "BitMasking.h"
#include <iostream>

CBitMasking::CBitMasking(BYTE& mask) :m_Mask(mask)
{

}

void CBitMasking::SetBit(Bits bits)
{
	m_Mask |= 1 << bits;
}

void CBitMasking::ClearBit(Bits bits)
{
	m_Mask &= ~(1 << bits);
}

void CBitMasking::ToggleBit(Bits bits)
{
	m_Mask ^= 1 << bits;
} bool CBitMasking::CheckBit(Bits bits) {
	return (m_Mask >> bits) & 1;
}

void CBitMasking::Display()
{
	for (int i = 7; i >= 0; i--)
	{
		std::cout << CheckBit(Bits(i)) ? "1" : "0";
	}
}