#include <windows.h>

//#include "global_header.h"
#include "variable.h"
#include "header.h"
#include "function.h"
#include "anti.h"
#include <stdio.h>

ClsBox DllBox2;

DWORD dInput = (DWORD)GetModuleHandle("dinput8.dll");
int BU_KEYPRESS = 128;
int BU_KEYUP = 0;
bool AutoOn = false;
int vAuto = 0;

#define TIMESPACE__	0x5EF4

DWORD RD(DWORD dwAddress)
{
	DWORD dwValue;
	ReadProcessMemory(GetCurrentProcess(),(LPCVOID)dwAddress,&dwValue,4,0);
	return dwValue;
}
void WD(DWORD dwAddress,DWORD dwValue)
{
	WriteProcessMemory(GetCurrentProcess(),(LPVOID)dwAddress,&dwValue,4,0);
}
void PatchMem(DWORD address, DWORD value)
{
	DWORD dwOldProtect; DWORD tmpProtect;
	if(VirtualProtectEx(GetCurrentProcess(),(LPVOID)address,sizeof(value),4,&dwOldProtect))
	{	
		if (!IsBadWritePtr((LPVOID)address,4))
		{
			*(DWORD*)address = value;
		VirtualProtectEx(GetCurrentProcess(),(LPVOID)address,sizeof(value),dwOldProtect,&tmpProtect);
		}
	}
}

void MySendKey1()
{
	DllBox2.WriteMemoryProcess(KEYMAP_1_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_1_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_1_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_1_2), &BU_KEYUP, 1, 0);
}
void MySendKey3()
{
	DllBox2.WriteMemoryProcess(KEYMAP_3_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_3_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_3_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_3_2), &BU_KEYUP, 1, 0);
}
void MySendKey4()
{
	DllBox2.WriteMemoryProcess(KEYMAP_4_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_4_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_4_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_4_2), &BU_KEYUP, 1, 0);
}
void MySendKey5()
{
	DllBox2.WriteMemoryProcess(KEYMAP_5_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_5_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_5_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_5_2), &BU_KEYUP, 1, 0);
}
void MySendKey6()
{
	DllBox2.WriteMemoryProcess(KEYMAP_6_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_6_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_6_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_6_2), &BU_KEYUP, 1, 0);
}
void MySendKey7()
{
	DllBox2.WriteMemoryProcess(KEYMAP_7_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_7_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_7_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_7_2), &BU_KEYUP, 1, 0);
}
void MySendKey9()
{
	DllBox2.WriteMemoryProcess(KEYMAP_9_1, &BU_KEYPRESS, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_9_2), &BU_KEYPRESS, 1, 0);
	Sleep(5);
	DllBox2.WriteMemoryProcess(KEYMAP_9_1, &BU_KEYUP, 1, 0);
	DllBox2.WriteMemoryProcess((dInput + KEYMAP_9_2), &BU_KEYUP, 1, 0);
}
void SetSendKey(int key)
{
	switch(key){
		case 1:
			MySendKey1();break;
		case 4:
			MySendKey4();break;
		case 7:
			MySendKey7();break;
		case 9:
			MySendKey9();break;
		case 6:
			MySendKey6();break;
		case 3:
			MySendKey3();break;
		case 5:
			MySendKey5();break;
	}
}
void WriteMemoryProcess(DWORD dwAddress, LPCVOID buffer, size_t size, SIZE_T *size_)
{
	DWORD dwOldProtect;
	void* vAddress = (void*)dwAddress;
	if (VirtualProtect(vAddress, size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, buffer, size, size_);
		//VirtualProtect(vAddress, size, dwOldProtect, 0);
	}
}
int setadmin = 0;
//int AutoBUMain()
//{
//	DWORD OffsetAuto = 0x30;
//	int result;
//	int AddressBase;
//	int space_time;
//	bool F11PRESS = true;
//	while(1){
//		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(BUCOUNT), &AddressBase, 4, 0);
//		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(AddressBase + (TIMESPACE__ + OffsetAuto)), &space_time, 4, 0);
//		if (GetAsyncKeyState(VK_F3)){
//			AutoOn = true;
//			vAuto++;
//		}
//		if (GetAsyncKeyState(VK_F4)){
//			AutoOn = false;
//			result = 0;
//		}
//		if (AutoOn){
//			if (space_time < 1){
//				SetSendKey(5);
//			}
//		//Canh Phim
//		DWORD i=0;
//		DWORD v=RD(RD(RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5EDC + OffsetAuto)+4*i)+0x20);
//		while(v>=0 && v<=6)
//		{
//			i++;
//			v=RD(RD(RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5EDC + OffsetAuto)+4*i)+0x20);
//		}
//		DWORD del=RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5F7C + OffsetAuto);
//		DWORD left,right;
//		del>0?left=316:left=396;
//		right=1024-left;
//
//		
//		DWORD Time=RD(RD(RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5EDC + OffsetAuto)+4*i)+0x14);
//		if((Time > left && Time < left+40) || (Time > right-40 && Time< right) )
//		{
//			DWORD key=RD(RD(RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5EDC + OffsetAuto)+4*i)+0x8);
//			DWORD delC=RD(RD(RD(RD(RD(BASE_INFOMATION)+0x1C)+0x5EDC + OffsetAuto)+4*i)+0x1C);
//			if(delC!=1)
//				SetSendKey(key);
//		}
//		}
//		Sleep(1);
//	}
//	return 0;
//}
int AutoBUMain()
{
	while(1){
	DWORD OffsetAuto = 0x30;
	DWORD Base_1 = 0;
	DWORD Base_2 = 0;
	DWORD Base_3 = 0;
	char notice[] = "keydel";
	char deldefault[]= "찬스버튼_3";
		if (GetAsyncKeyState(VK_INSERT)){
			AutoOn = true;
		}
		if (GetAsyncKeyState(VK_ESCAPE)){
			AutoOn = false;
		}
		if (AutoOn){

		DWORD KEYON = 1;
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(BASE_INFOMATION), &Base_1, 4, 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(Base_1 + 0x1C), &Base_2, 4, 0);
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)(Base_2 + (0x5F7C + OffsetAuto)), &KEYON, 4, 0);

		//WriteProcessMemory(GetCurrentProcess(), (LPVOID)DELNOTICE, &notice, sizeof(notice), 0);
		}else{
			//WriteProcessMemory(GetCurrentProcess(), (LPVOID)DELNOTICE, &deldefault, sizeof(deldefault), 0);
		}
	Sleep(10);
	}
	return 0;
}