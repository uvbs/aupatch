
#include <windows.h>
#include <fstream>
#include <stdio.h>

void *DetourFunc(BYTE *src, const BYTE *dst, const int len)
{
	BYTE *jmp = (BYTE*)malloc(len+5); //tao vung nho voi kich thuoc len + 5
	DWORD dwback;

	VirtualProtect(src, len, PAGE_READWRITE, &dwback);//thay doi dac tinh vung nho

	memcpy(jmp, src, len);	//chuyen source vao jmp
	jmp += len; //jmp = jmp + len
	
	jmp[0] = 0xE9; //byte 1 : 0xE9 ={asm : jmp}
	*(DWORD*)(jmp+1) = (DWORD)(src+len - jmp) - 5;

	src[0] = 0xE9;
	*(DWORD*)(src+1) = (DWORD)(dst - src) - 5;

	VirtualProtect(src, len, dwback, &dwback);

	return (jmp-len);
}

bool RetourFunc(BYTE *src, BYTE *restore, const int len)
{
	DWORD dwback;
		
	if(!VirtualProtect(src, len, PAGE_READWRITE, &dwback))	{ return false; }
	if(!memcpy(src, restore, len))							{ return false; }

	restore[0] = 0xE9;
	*(DWORD*)(restore+1) = (DWORD)(src - restore) - 5;

	if(!VirtualProtect(src, len, dwback, &dwback))			{ return false; }
	
	return true;
}	