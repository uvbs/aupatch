
//http://stackoverflow.com/questions/17685466/http-request-by-sockets-in-c
#include <windows.h>
#include <process.h> 
#include <stdio.h>
#include <fstream>
#include <wininet.h>
#include <imagehlp.h>
#include <iostream>
#include <string>
#include <wininet.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <tchar.h>
#include <CkByteData.h>
#include <UrlMon.h>

//#include "Applehacker.h"
//#include "BeatUp.h"
#include "function.h"
#include "main.h"
#include "header.h"
#include "variable.h"
#include "d3d9.h"
#include "kill.h"
#include "anti.h"
//#include "resource.h"

#define	HN_SERVER	"/T3ENTER 17007D3E04744F4B003B4E6D71043E527974032E467973 DBE47882993EF878D06EA27C6AC6842D652411AC7A33DD362C1949A3E165B644"
#define	TP_SERVER	"/T3ENTER 1400FE684E5572576C517154685D7B5A645A755A EF4E9A7C229C9A0E0CB2E8006B840122B0300576FE8581B140661D4193FC490A"

#define	WIN		1500
#define	LOSE	500

#define	MEDAL_GM	4
#define MEDAL_GOLD	128
#define MEDAL_SILVER	64
#define MEDAL_BRONZE	32
#define MEDAL	116
#define MEDAL_STAR_HERO	16
#define MEDAL_MUSIC	8192
#define MEDAL_BEATUP	1024
#define MEDAL_GOLD_KEY	65536
#define MEDAL_SILVER_KEY	(MEDAL_STAR_RED * 2)
#define MEDAL_BRONZE_KEY	(MEDAL_STAR_YELLOW * 2)
#define FULL_MEDAL (MEDAL_GM + MEDAL_GOLD + MEDAL_BEATUP + MEDAL_MUSIC)

#define	ACVSIZE	55522096
#define	BASE 0x28

#define	BU_ARTIST_TITLE	0x4
#define	BU_SONG_TITLE	0x84
#define	BU_BPM 0x184
#define	BU_OFFSET 0x18C
#define	BU_NEW 0x190
#define	BU_USE 0x194
#define	BU_LEVEL 0x188

#define	NORMAL_ARTIST_TITLE 0x4
#define	NORMAL_SONG_TITLE 0x84
#define	NORMAL_START_MADI 0x184
#define	NORMAL_BPM 0x18C
#define	NORMAL_USE 0x190
#define	NORMAL_BGM 0x228

#define LOGFILE	"log.txt"

//#define BeatUpSize	(sizeof(BeatUpData)/sizeof(BeatUpData[0]))
//#define	NormalSize	(sizeof(NormalData)/sizeof(NormalData[0]))

#pragma comment(lib, "urlmon.lib")
//#include "global_header.h"
#define DLLEXPORT __declspec(dllexport)
//#pragma data_seg (".mydata")
HHOOK g_hHookKbdLL = NULL; // hook handle
using namespace std;
//DWORD dInput8 = (DWORD)GetModuleHandle("dinput8.dll");

//#pragma data_seg(".shared")
//HHOOK hGlobalHook;
//#pragma data_seg()

//#define NT_SUCCESS(x) ((x) >= 0)
//#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
//#define SystemHandleInformation 16
//#define ObjectBasicInformation 0
//#define ObjectNameInformation 1
//#define ObjectTypeInformation 2
//#define fcExp            0x4D9480
//#define BaseAddr        0x400000

HANDLE ThreadKill_11 = 0;
char *buffer_acv;
DWORD dwPassword;
char PASSWORD[100];
bool NUMPAD1 = true;
bool NUMPAD4 = true;
bool NUMPAD7 = true;
bool NUMPAD9 = true;
bool NUMPAD6 = true;
bool NUMPAD3 = true;
HANDLE Thread_main_1 = 0;
HANDLE Thread_main_2 = 0;
HANDLE Thread_main_3 = 0;

ofstream log(LOGFILE);
ClsBox DllBox;
stDATA	STDATA;
DEVMODE devPrevMode;
BOOL    bPrevSet = FALSE;
char *source_data = new char[100];
char *global_name_1 = new char[100];
char *global_name_2 = new char[100];
char *global_name_3 = new char[100];
char *global_name_4 = new char[100];
char *global_name_5 = new char[100];
char *global_name_6 = new char[100];

typedef int (__cdecl *SetPointerHook)(int, int);
static SetPointerHook SetPointerAudition;
typedef int (__cdecl *SetDirectHook)(char *);
static SetDirectHook SetDirect;

typedef int (__cdecl *CreateDeviceHook)();
static CreateDeviceHook CreateHook;
typedef int (__stdcall *pMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
static pMessageBox hMessageBox;
typedef BOOL (__stdcall *pTerminateProcess)(HANDLE, UINT);
static pTerminateProcess hTerminateProcess;
typedef HINSTANCE (*pShellExecute)(HWND, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR, INT);
static pShellExecute hShellExecute;
typedef int (__stdcall *pFSOUND_Stream_Open)(const char *, int, int, int);
static pFSOUND_Stream_Open hFSOUND_Stream_Open;
typedef int (__cdecl *pCsvDump)(const char *, const char *);
static pCsvDump	hCsvDump;
typedef int (__stdcall *pFSOUND_Stream_GetLengthMs)(int);
static pFSOUND_Stream_GetLengthMs hFSOUND_Stream_GetLengthMs;
typedef int (__stdcall *pFSOUND_Stream_GetTime)(int);
static pFSOUND_Stream_GetTime hFSOUND_Stream_GetTime;
typedef void (__cdecl *pHookAudition)(int, int, int);
static pHookAudition hHookAudition;

byte *CG_WriteProcessMemory = NULL;
typedef int (__stdcall *MYWriteProcessMemory)(HANDLE hProcess,LPVOID lpBaseAddress,
											LPCVOID lpBuffer,SIZE_T nSize,
											SIZE_T *lpNumberOfBytesWritten);
byte *CG_VirtualProtect = NULL;
byte *CG_CheckSumMappedFile = NULL;
typedef int (__stdcall *MyCheckSumMappedFile)(PVOID BaseAddress,DWORD FileLength,PDWORD HeaderSum,PDWORD CheckSum);
typedef int (__stdcall *MYVirtualProtect)(LPVOID lpAddress,SIZE_T dwSize,
											DWORD flNewProtect,PDWORD lpflOldProtect);
BOOL killXTRAP();
int Section[] = {0x1, 
				0x191, 
				0x4B1, 
				0x6CD + 0x3C, 
				0x571 + 0x30 + 0xA0, 
				0x2B9 + 0x18 + 0x50}; //pointer for character here
void hThread_main();
void BUPatchConnect();
void ThreadKillXTrap();
BOOL __stdcall NewTextOutA(HDC hdc, int x, int y, LPCSTR lpString, int c);
BOOL __stdcall NewGetTextExtentPointA(HDC hdc, LPCSTR lpString, int c, LPSIZE lpsz);
int __stdcall FSOUND_Stream_Open(const char *file_or_data, int mode, int offset, int length);
int __cdecl CsvDump(const char *filename, const char *Mode);
HANDLE hHandle = GetCurrentProcess();

int setmenu = 1;
int *ret_table = new int[6];
int *rev_score = new int[6];
int *npc_score = new int[1];
//char *info = new char[100];
int perfect, great, cool, bad, miss, xPer, xMax = 0;
int LENGTH = 0;
int WIDTH = 0;
int BONUS_LENGTH = 0;
int BONUS_WIDTH = 0;
int LINE = 20;
int X = 157;
int Y = 10;
int XX = X;
int YY = Y;
char *win_lose = new char[100];
int NPC_Number = 0;

int __cdecl sub_704510()
{
	CreateHook = (CreateDeviceHook)(0x704510);
	return CreateHook();
}
int XMax()
{
	return xMax;
}
char *winlose()
{
	return win_lose;
}
float percent = 0.f;
char table[100];
char boss_count[10];
char player_count[10];
int COUNT_PLAY_BOSS = 0;
int COUNT_PLAY_PLAYER = 0;
int winmode = 0;
int fpsboot = 0;
int total_score = 0;
void mThread()
{
	while(1){
	if (!*(DWORD*)STARTGAME) NPC_Number = NPC();
	//winmode = GetPrivateProfileInt("CONFIG", "WINMODE", 0, ".\\config.ini");
	//fpsboot = GetPrivateProfileInt("CONFIG", "fpsboot", 0, ".\\config.ini");
	//if (winmode != 0 || fpsboot != 0){
	//	LENGTH = 800;
	//	WIDTH = 600;
	//	BONUS_LENGTH = 70;
	//	BONUS_WIDTH = 70;
	//	LINE = 15;
	//}
	if (*(DWORD*)STARTGAME){
			if (GetAsyncKeyState(VK_F5)) setmenu = 1;
			if (GetAsyncKeyState(VK_F6)) setmenu = 0;

			ret_table = result_count();

			if (ret_table[5] > 0){
				if (perfect < ret_table[0]){perfect++; xPer++;}
				if (great < ret_table[1]){great++; xPer = 0;}
				if (cool < ret_table[2]){cool++; xPer = 0;}
				if (bad < ret_table[3]){bad++; xPer = 0;}
				if (miss < ret_table[4]){miss++; xPer = 0;}
				//if (xMax < xPer) xMax = xPer;
			}
			rev_score = score();
			npc_score = npcscore();
			total_score = rev_score[0] + rev_score[1] + rev_score[2] + rev_score[3] + rev_score[4] + rev_score[5];
			
			if (total_score > npc_score[0])
				sprintf(win_lose, "win");
			else
				sprintf(win_lose, "lose");

			if (npc_score[0] >= total_score){
				sprintf(boss_count, "[1]");
				COUNT_PLAY_BOSS = 0;
			}else{
				sprintf(boss_count, "[2]");
				COUNT_PLAY_BOSS = LINE;
			}
			if (npc_score[0] >= total_score){
				sprintf(player_count, "[2]");
				COUNT_PLAY_PLAYER = LINE;
			}else{
				sprintf(player_count, "[1]");
				COUNT_PLAY_PLAYER = 0;
			}
			percent = (float)ret_table[0] * 100 / (ret_table[0] + ret_table[1] + ret_table[2] + ret_table[3] + ret_table[4]);

		}else{
				total_score = 0;
				xPer = 0;
				perfect = 0;
				great = 0;
				cool = 0;
				bad = 0;
				miss = 0;
				xMax = 0;
				memset(ret_table, 0, sizeof(ret_table));
				//info = Info();
				//sprintf(table, "%s", info);
		}
	Sleep(10);
	}
}
void RoomNameChange()
{
	while(1){
		for(int i = 0; i < sizeof(roomName)/sizeof(roomName[0]); i++){
			if (strcmp(roomName[i].text, (char *)CHAT) == 0){
				DllBox.WriteMemoryProcess((DWORD)CHAT, &ROOMNAME, sizeof(ROOMNAME), 0);
			}
		}
		Sleep(100);
	}
}
int gift()
{
	return WIN;
}
//DLLEXPORT BOOL Is_KBD_Disabled()
//{
//	return g_hHookKbdLL != NULL;
//}
//
//DLLEXPORT BOOL T3_KBD_Disable(BOOL bDisable, BOOL bBeep)
//{
//	return Is_KBD_Disabled();
//}
//void ClsBox::set_data()
//{
//	DWORD BeatUp_Memory[BeatUpSize];
//	DWORD Normal_Memory[NormalSize];
//	DWORD dwBeatUpBase[2];
//	DWORD dwNormalBase[2];
//
//	ClsBox::RM((LPCVOID)BEATUPDATA, &dwBeatUpBase[0], 4, 0);
//	ClsBox::RM((LPCVOID)(dwBeatUpBase[0] + BASE), &dwBeatUpBase[1], 4, 0);
//	ClsBox::RM((LPCVOID)NORMALDATA, &dwNormalBase[0], 4, 0);
//	ClsBox::RM((LPCVOID)(dwNormalBase[0] + BASE), &dwNormalBase[1], 4, 0);
//	for (int i = 0; i < BeatUpSize; i++){
//		ClsBox::RM((LPCVOID)(dwBeatUpBase[1] + (4 *i)), &BeatUp_Memory[i], 4, 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_ARTIST_TITLE), BeatUpData[i].Singer, 50, 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_SONG_TITLE), BeatUpData[i].Songtitle, 50, 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_BPM), &BeatUpData[i].BPM, sizeof(float), 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_LEVEL), &BeatUpData[i].LEVEL, sizeof(int), 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_NEW), &BeatUpData[i].NEW, sizeof(int), 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_USE), &BeatUpData[i].Use, sizeof(int), 0);
//		ClsBox::WriteMemoryProcess((BeatUp_Memory[i] + BU_OFFSET), &BeatUpData[i].Offset, sizeof(float), 0);
//	}
//	for (int i = 0; i < NormalSize; i++){
//		ClsBox::RM((LPCVOID)(dwNormalBase[1] + (4 *i)), &Normal_Memory[i], 4, 0);
//		ClsBox::WriteMemoryProcess((Normal_Memory[i] + NORMAL_ARTIST_TITLE), NormalData[i].MUSICNAME1, 50, 0);
//		ClsBox::WriteMemoryProcess((Normal_Memory[i] + NORMAL_SONG_TITLE), NormalData[i].MUSICNAME2, 50, 0);
//		ClsBox::WriteMemoryProcess((Normal_Memory[i] + NORMAL_BPM), &NormalData[i].BPM, sizeof(float), 0);
//		ClsBox::WriteMemoryProcess((Normal_Memory[i] + NORMAL_START_MADI), &NormalData[i].STARTMADI, sizeof(int), 0);
//		ClsBox::WriteMemoryProcess((Normal_Memory[i] + NORMAL_USE), &NormalData[i].USE, sizeof(int), 0);
//	}
//}
BOOL ClsBox::RM(LPCVOID lpAddress, LPVOID buffer, SIZE_T size, SIZE_T *lpSize)
{
	return ReadProcessMemory(hHandle, lpAddress, buffer, size, lpSize);
}
void ClsBox::mySprintf(char *buffer, const char *format, ...)
{
  va_list args;
  va_start (args, format);
  vsprintf (buffer,format, args);
  perror (buffer);
  va_end (args);
}
int __cdecl CsvDump(const char *filename, const char *Mode)
{
	DllBox.GUITAR_TBM = filename;
	BYTE guitardefault[] = {0x87, 0xB8, 0xBF, 0xFF};
	DllBox.WriteMemoryProcess((DWORD)(OffsetCSV + 0x1), &guitardefault, sizeof(guitardefault), 0);
	return hCsvDump(filename, Mode);
}
BOOL ClsBox::SetScreenResolution(int nWidth, int nHeight)
{
    DEVMODE devMode;
    ZeroMemory(&devMode, sizeof(DEVMODE));
    devMode.dmSize = sizeof(DEVMODE);
    if(!EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &devMode))
        return FALSE;
    CopyMemory(&devPrevMode, &devMode, sizeof(DEVMODE));
    bPrevSet             = TRUE;
    devMode.dmPelsWidth  = nWidth;
    devMode.dmPelsHeight = nHeight;
    return (ChangeDisplaySettingsEx(NULL, &devMode, NULL, 0, NULL) == DISP_CHANGE_SUCCESSFUL);
}
BOOL ClsBox::RestoreScreenResolution(VOID)
{
    if(bPrevSet)
        return (ChangeDisplaySettingsEx(NULL, &devPrevMode, NULL, 0, NULL) == DISP_CHANGE_SUCCESSFUL);
    return FALSE;
}
BOOL WINAPI NewPtInRect(RECT *lprc, POINT pt)
{
	return PtInRect(lprc, pt);
}
BOOL WINAPI NewSetRect(LPRECT lprc,int xLeft,int yTop,int xRight,int yBottom)
{
	xRight = 800;
	yBottom = 600;
	xLeft = 0;
	yTop = 0;
	return SetRect(lprc,xLeft,yTop,xRight,yBottom);
}
BOOL WINAPI NewAdjustWindowRect(LPRECT lpRect,DWORD dwStyle,BOOL bMenu)
{
	lpRect->right = 800;
	lpRect->bottom = 600;
	return AdjustWindowRect(lpRect,dwStyle,bMenu);
}
HFONT __stdcall NewCreateFontA(int cHeight, int cWidth, int cEscapement, int cOrientation, int cWeight, DWORD bItalic, DWORD bUnderline, DWORD bStrikeOut, DWORD iCharSet, DWORD iOutPrecision, DWORD iClipPrecision, DWORD iQuality, DWORD iPitchAndFamily, LPCSTR pszFaceName)
{
	return CreateFontA(12, cWidth, cEscapement, cOrientation, 0, bItalic, bUnderline, bStrikeOut, iCharSet, iOutPrecision, iClipPrecision, iQuality, iPitchAndFamily, "Tahoma");
}
//HWND WINAPI NewCreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int   X, int   Y, int   nWidth, int   nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
//{
//	return HWNDHOOK();
//}
BOOL __stdcall NewShowWindow(HWND hWnd, int nCmdShow)
{
	return ShowWindow(hWnd, 0);
}
HANDLE __stdcall NewCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (strcmp(lpFileName, OLDACV) == 0){
		lpFileName = NEWACV;
	}
	if (strstr(lpFileName, "tbm") > 0 || strstr(lpFileName, "abm") > 0)
	{
		DllBox.GetTbmFilePath = (char *)lpFileName + 4;
		if (strstr(DllBox.GAME_TYPE_GLOBAL, "guitar") > 0){
			char *TbmGuitarPath = (char *)lpFileName + 6;
			sprintf(DllBox.GetTbmFileGuitar, "%.04s", TbmGuitarPath);
		}
	}
	if (!*(DWORD*)STARTGAME) {
		if (strstr(lpFileName, "tbm") > 0 || strstr(lpFileName, "abm") > 0)
		{
			DllBox.TbmBGM = (char *)lpFileName + 4;
		}
	}
	if (strstr(DllBox.GAME_TYPE_GLOBAL, "guitar") == 0 ||
		strstr(DllBox.GAME_TYPE_GLOBAL, "beatup6") == 0	||
		strstr(DllBox.GAME_TYPE_GLOBAL, "12easy") == 0	||
		strstr(DllBox.GAME_TYPE_GLOBAL, "12hard") == 0	||
		strstr(DllBox.GAME_TYPE_GLOBAL, "blockbeat") == 0 ||
		strstr(DllBox.GAME_TYPE_GLOBAL, "spacepangpang") == 0)
	{
		if (strstr(lpFileName, "tbm") > 0 || strstr(lpFileName, "abm") > 0)
		{
			DllBox.TbmNormalFile = (char *)lpFileName + 4;
		}
	}
	return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
BOOL __stdcall NewTextOutA(HDC hdc, int   x, int   y, LPCSTR lpString, int   c)
{
	for(int i =0; i < sizeof(DATA_TEXT)/sizeof(DATA_TEXT[0]); i++){
		char compare[500];
		sprintf(compare, "%s : ", DATA_TEXT[i].text);
		if (strstr(lpString, compare) > 0){
			char source[500];
			char *main = (char *)(lpString + strlen(DATA_TEXT[i].text) + 3);
			sprintf(source, "%s : %s", DATA_CHANGE[i].text, main);
			c = strlen(source);
			lpString = source;
		}
	}
	int admin_kick_number = 0;
	if (strstr(lpString, DATA_TEXT[11].text) != 0){
		lpString = DATA_CHANGE[11].text;
		c = strlen(DATA_CHANGE[11].text);
	}
	for (int i = 0; i < sizeof(DATA_TEXT)/sizeof(DATA_TEXT[0]); i++)
	{
		if (strcmp(lpString, DATA_TEXT[i].text) == 0){
			lpString = DATA_CHANGE[i].text;
			c = strlen(lpString);
		}
	}
	for(int i = 0; i < sizeof(ADMIN_KICK)/sizeof(ADMIN_KICK[0]); i++){
		if (strcmp(DllBox.GameAccount, ADMIN_KICK[i].text) == 0){
			admin_kick_number++;
		}
	}
	if (admin_kick_number == 0){
		if (strstr(lpString, "Audition Patch Admin [Hnnp] : kick!") > 0 || strstr(lpString, "(†iêÒu¯®¯†ýÒ) : kick!") > 0){
			DllBox.MyTerminateProcess(hHandle, 0);
		}
	}
	return TextOutA(hdc, x, y, lpString, c);
}
BOOL __stdcall NewGetTextExtentPointA(HDC hdc, LPCSTR lpString, int   c, LPSIZE lpsz)
{
	for(int i =0; i < sizeof(DATA_TEXT)/sizeof(DATA_TEXT[0]); i++){
		char compare[500];
		sprintf(compare, "%s : ", DATA_TEXT[i].text);
		if (strstr(lpString, compare) > 0){
			char source[500];
			char *main = (char *)(lpString + strlen(DATA_TEXT[i].text) + 3);
			sprintf(source, "%s : %s", DATA_CHANGE[i].text, main);
			c = strlen(source);
			lpString = source;
		}
	}
	if (strstr(lpString, DATA_TEXT[11].text) != 0){
		lpString = DATA_CHANGE[11].text;
		c = strlen(DATA_CHANGE[11].text);
	}
	for (int i = 0; i < sizeof(DATA_TEXT)/sizeof(DATA_TEXT[0]); i++)
	{
		if (strcmp(lpString, DATA_TEXT[i].text) == 0){
			lpString = DATA_CHANGE[i].text;
			c = strlen(lpString);
		}
	}
	for (int i = 0; i < sizeof(LOAD_DATA_NOTKICK)/sizeof(LOAD_DATA_NOTKICK[0]); i++)
	{
		char NOTKICK_DATA[100];
		sprintf(NOTKICK_DATA, ERROR_RESULT[1].text, LOAD_DATA_NOTKICK[i].text);
		if (strncmp(lpString, NOTKICK_DATA, strlen(NOTKICK_DATA)) == 0)
		{
			DllBox.MyMessageBox("Not kick ADMIN!", "ADMIN", 0);
			DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
		}
	}
	return GetTextExtentPointA(hdc, lpString, c, lpsz);
}
int __stdcall FSOUND_Stream_Open(const char *file_or_data, int mode, int offset, int length)
{
	if (*(DWORD*)STARTGAME) //if game start
	{
		DllBox.PLAY++;
		char RemoteMusic[100];
		char RemoteSave[100];
		if (strcmp(file_or_data, "sound/load_ingame.mp3") != 0)
		{
			/*-------------------------------------------------------------------------*/
			if (strstr(DllBox.GAME_TYPE_GLOBAL, "beatup6") > 0	||
				strstr(DllBox.GAME_TYPE_GLOBAL, "12easy") > 0	||
				strstr(DllBox.GAME_TYPE_GLOBAL, "12hard") > 0	||
				strstr(DllBox.GAME_TYPE_GLOBAL, "blockbeat") > 0 ||
				strstr(DllBox.GAME_TYPE_GLOBAL, "spacepangpang") > 0)
			{
				char TbmFile[50];
				sprintf(TbmFile, "%s", DllBox.GetTbmFilePath); //get tbm file to need
				sprintf(RemoteSave, SERVERSAVE, TbmFile);//save
				sprintf(RemoteMusic, SERVERMUSIC, TbmFile);//link
				if (DllBox.MConnect(RemoteMusic, RemoteSave)){//download
					if (DllBox.FileExist(RemoteSave)) //if file exist
					{
						FILE *hFile = fopen(RemoteSave, "rb");
						fseek(hFile, 0, SEEK_END);
						int length = ftell(hFile) - 9;
						char *buffer = (char *)malloc(length);
						fclose(hFile);
						buffer = DllBox.LoadMusicResource(RemoteSave);
						DllBox.OggS = hFSOUND_Stream_Open(buffer, LOAD_MEMORY, offset, length);
					}else{
						DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
					}
				}
			}else if(strstr(DllBox.GAME_TYPE_GLOBAL, "guitar") > 0){
				//code guitar here
				if (DllBox.PLAY == 2)
				{
					char GUITAR_MAIN[100];
					sprintf(GUITAR_MAIN, "%ss.tbm", DllBox.GetTbmFileGuitar);
					sprintf(RemoteSave, SERVERSAVE, GUITAR_MAIN);//save
					sprintf(RemoteMusic, SERVERMUSIC, GUITAR_MAIN);
					if (DllBox.MConnect(RemoteMusic, RemoteSave)){
						if (DllBox.FileExist(RemoteSave))
						{
							FILE *hFile = fopen(RemoteSave, "rb");
							fseek(hFile, 0, SEEK_END);
							int length = ftell(hFile) - 9;
							char *mainbuffer = (char *)malloc(length);
							fclose(hFile);
							mainbuffer = DllBox.LoadMusicResource(RemoteSave);
							DllBox.OggS = hFSOUND_Stream_Open(mainbuffer, LOAD_MEMORY, 0, DllBox.length);
						}else{
							DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
						}
					}
				}
				Sleep(1000);
				if (DllBox.PLAY == 3)
				{
					char GUITAR_SOUND[100];
					sprintf(GUITAR_SOUND, "%sg.tbm", DllBox.GetTbmFileGuitar);
					sprintf(RemoteSave,  SERVERSAVE, GUITAR_SOUND);//save
					sprintf(RemoteMusic, SERVERMUSIC, GUITAR_SOUND);
					if (DllBox.MConnect(RemoteMusic, RemoteSave)){
						if (DllBox.FileExist(RemoteSave))
						{
							FILE *hFile = fopen(RemoteSave, "rb");
							fseek(hFile, 0, SEEK_END);
							int length = ftell(hFile) - 9;
							char *soundbuffer = (char *)malloc(length);
							fclose(hFile);
							soundbuffer = DllBox.LoadMusicResource(RemoteSave);
							DllBox.OggS = hFSOUND_Stream_Open(soundbuffer, LOAD_MEMORY, 0, DllBox.length);
						}else{
							DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
						}
					}
				}
			}else{
					char *TbmNormalPath = new char[100];
					sprintf(TbmNormalPath, SERVERSAVE, DllBox.TbmNormalFile);
					if (DllBox.FileExist(TbmNormalPath))
					{
						FILE *hFile = fopen(TbmNormalPath, "rb");
						fseek(hFile, 0, SEEK_END);
						int length = ftell(hFile) - 9;
						char *soundbuffer = (char *)malloc(length);
						fclose(hFile);
						soundbuffer = DllBox.LoadMusicResource(TbmNormalPath);
						DllBox.OggS = hFSOUND_Stream_Open(soundbuffer, LOAD_MEMORY, 0, DllBox.length);
					}else{
						DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
					}
			}
			/*-------------------------------------------------------------------------*/
		}else{ //if not loading ingame .mp3
			DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
		}
	}else{ //if game end
		char *TbmBGMPath = new char[100];
		sprintf(TbmBGMPath, SERVERSAVE, DllBox.TbmBGM);
		if (DllBox.FileExist(TbmBGMPath))
		{
			FILE *hFile = fopen(TbmBGMPath, "rb");
			fseek(hFile, 0, SEEK_END);
			int length = ftell(hFile) - 9;
			char *soundbuffer = (char *)malloc(length);
			fclose(hFile);
			soundbuffer = DllBox.LoadMusicResource(TbmBGMPath);
			DllBox.OggS = hFSOUND_Stream_Open(soundbuffer, LOAD_MEMORY, 0, DllBox.length);
		}else{
			DllBox.OggS = hFSOUND_Stream_Open(file_or_data, mode, offset, length);
		}
	}
	return DllBox.OggS;
}
int ClsBox::FileExist(char *FileName)
{
	if (GetFileAttributes(FileName) == 0xffffffff)
		return 0;
	else
		return 1;
}
int ClsBox::GetMusicStatus(int OggS)
{
	int lengthms = hFSOUND_Stream_GetLengthMs(OggS);
	int current = hFSOUND_Stream_GetTime(OggS);
	if (current == lengthms)
		return 1;
	return 0;
}
void ClsBox::LoadTitle()
{
	if (!(*(DWORD*)STARTGAME)){
		DWORD dwBase;
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(BASE_INFOMATION), &dwBase, 4, 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(dwBase + SONGTITLE), &DllBox.SONG_TITLE, sizeof(DllBox.SONG_TITLE), 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(dwBase + ARTISTTITLE), &DllBox.ARTIST_TITLE, sizeof(DllBox.ARTIST_TITLE), 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(dwBase + BPMTITLE), &DllBox.BPM_TITLE, sizeof(DllBox.BPM_TITLE), 0);
		//DWORD NumberOfBytesWritten;
		//HANDLE hObject = CreateFileA("memory.txt", GENERIC_WRITE | FILE_ADD_FILE, 0, 0, CREATE_ALWAYS, 0x80, 0);
		//WriteFile(hObject, DllBox.SONG_TITLE, 1000, &NumberOfBytesWritten, 0);
		//CloseHandle(hObject);
	}
}
DWORD KillXTrapXT()
{
	HWND hwndA = FindWindow("X-Trap(GameSecurity_Pinky_2009)",NULL);
	DWORD pid;
	GetWindowThreadProcessId(hwndA,&pid);
	return KillProcess(pid,1);
}
HINSTANCE ClsBox::MyShellExecute(HWND hwnd,LPCTSTR lpOperation,LPCTSTR lpFile, LPCTSTR lpParameters,LPCTSTR lpDirectory,INT nShowCmd)
{
	return hShellExecute(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}
void ClsBox::DecodeACV(const char *Input)
{
	int key_1 = 0x11445256;
	int key_2 = 0x24521456;
	int key_3 = 0x33212455;
	FILE *file_in = fopen(Input, "rb");
	fseek(file_in, 0, SEEK_END);
	int length = ftell(file_in);
	fseek(file_in, 0, SEEK_SET);
	buffer_acv = new char[length];
	fread(buffer_acv, length, 1, file_in);
	for (int i = 0; i < length; i++)
	{
		buffer_acv[i] = buffer_acv[i] ^ (i * i) ^ key_1 ^ key_2 ^ key_3 ^ (i + i);
	}
	fclose(file_in);
	//DllBox.DATA_051ACV = (LPVOID)buffer;
}
char *ClsBox::replace(const char *s, const char *old, const char *newstr)
{
	char *ret;
	int i, count = 0;
	size_t newlen = strlen(newstr);
	size_t oldlen = strlen(old);

	for (i = 0; s[i] != '\0'; i++) {
	if (strstr(&s[i], old) == &s[i]) {
	count++;
	i += oldlen - 1;
	}
	}

	ret = (char*)malloc(i + count * (newlen - oldlen));
	if (ret == NULL)
	exit(EXIT_FAILURE);

	i = 0;
	while (*s) {
	if (strstr(s, old) == s) {
	strcpy(&ret[i], newstr);
	i += newlen;
	s += oldlen;
	} else
	ret[i++] = *s++;
	}
	ret[i] = '\0';

	return ret;
}
int ClsBox::FindAndWriteBytes(char *value, DWORD dwStart, DWORD dwEnd)
{
	for ( int i = (int)dwStart; i < (int)dwEnd; i++)
	{
		if (strcmp((char *)(i), value) == 0)
		{
			char result[500];
			sprintf(result, "%x", i);
			
		}
	}
	return 0;
}
void __stdcall ClsBox::WriteMemoryProcess(DWORD dwAddress, LPCVOID buffer, size_t size, SIZE_T *size_)
{
	DWORD dwOldProtect;
	void* vAddress = (void*)dwAddress;
	if (VirtualProtect(vAddress, size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddress, buffer, size, size_);
		//VirtualProtect(vAddress, size, dwOldProtect, 0);
	}
}
DWORD ClsBox::AutoFindBytes(char *lpBuffer, DWORD dwStart, DWORD dwEnd)
{
	int len = strlen(lpBuffer);
	for (int i = (int)dwStart; i < (int)dwEnd; i++)
	{
		if (strncmp((char *)(i), lpBuffer, len) == 0)
			return i;
	}
	return 0;
}
DWORD ClsBox::AutoFindAddress(char *value, DWORD dwStart, DWORD dwEnd)
{
	for ( int i = (int)dwStart; i < (int)dwEnd; i++)
	{
		char result[100];
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(i), &result, sizeof(result), 0);
		if (strcmp(value, result) == 0)
		{
			return i;
		}
	}
	return 0;
}
void ClsBox::CallReplace(DWORD DiaChiLenhCall, DWORD DiaChiHamMoi)
{
	DWORD GiaTriSua, DiaChiSua;
	DiaChiSua = DiaChiLenhCall + 1;
	GiaTriSua = DiaChiHamMoi - DiaChiLenhCall - 5;
	DllBox.WriteMemoryProcess((DWORD)DiaChiSua, &GiaTriSua, 4, 0);
}
char *ClsBox::GetGameType()
{
	char *GAMETYPE = new char[100];
	switch(*(DWORD*)GAME_TYPE)
	{
		case GUITAR: GAMETYPE = "guitar";break;
			case BEATUP4: GAMETYPE = "beatup4";break;
				case BEATUP6: GAMETYPE = "beatup6";break;
					case ONETWOEASY: GAMETYPE = "12easy";break;
						case ONETWOHARD: GAMETYPE = "12hard";break;
							case BLOCKBEAT: GAMETYPE = "blockbeat";break;
								case SPACEPANGPANG: GAMETYPE = "spacepangpang";break;
									case NORMALPLAY: GAMETYPE = "normalplay";break;
	}
	return GAMETYPE;
}
char *ClsBox::LoadMusicResource(const char *TbmFile)
{
	int key1 = 0x114455;
	int key2 = 0x223350;
	int key3 = 0x852631;
	int hash = key1 ^ key2 ^ (key3 + 0x184);

	FILE *tbmopen = fopen(TbmFile, "rb");
	fseek(tbmopen, 0, SEEK_END);
	int length = ftell(tbmopen);
	length = length - 9;
	fseek(tbmopen, 9, SEEK_SET);
	char *buffer = (char *)malloc(length);
	fread(buffer, length, 1, tbmopen);
	for (int i = 0; i < length; i++)
	{
		buffer[i] = (int)buffer[i] ^ ((i + i) ^ hash) ^ (0x14452548 * i) ^ (length) ^ (0x878*i);
	}
	fclose(tbmopen);
	if (DllBox.FileExist(buffer))
	{
		int len = strlen(buffer);
		char *FileIn = (char *)malloc(len);
		FileIn = buffer;
		FILE *tbm = fopen(FileIn, "rb");
		fseek(tbm, 0, SEEK_END);
		int tbmlength = ftell(tbm);
		tbmlength = tbmlength - 9;
		fseek(tbm, 9, SEEK_SET);
		char *ret = (char *)malloc(tbmlength);
		fread(ret, tbmlength, 1, tbm);
		for (int i = 0; i < tbmlength; i++)
		{
			ret[i] = (int)ret[i] ^ ((i + i) ^ hash) ^ (0x14452548 * i) ^ (tbmlength) ^ (0x878*i);
		}
		DllBox.length = tbmlength;
		fclose(tbm);
		return ret;
	}
	DllBox.length = length;
	return buffer;
}
char *ClsBox::GetInfo()
{
	DWORD dwRead;
	char InfoLink[100];
	char *Buffer = (char *)malloc(1000);
	sprintf(InfoLink, HTTPINFO, DllBox.GameAccount);
	HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", InfoLink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	if(HttpSendRequest(hRequest, NULL, 0, NULL, 0)){
		InternetReadFile(hRequest, Buffer, 1000, &dwRead);
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hOpen);
		return Buffer;
	}
	return Buffer;
}
char *ClsBox::MedalInfo()
{
	DWORD dwRead;
	char *Buffer = (char *)malloc(1000);
	HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", MEDALINFO, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	if(HttpSendRequest(hRequest, NULL, 0, NULL, 0)){
		InternetReadFile(hRequest, Buffer, 1000, &dwRead);
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hOpen);
		return Buffer;
	}
	return Buffer;
}
int ClsBox::winlose(char *account, int coins, char *winlose)
{
		char httplink[100];
		sprintf(httplink, WINLOSE, account, coins, winlose);
		HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
		HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
		if (hConnect == NULL) return 2;
		HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
		if (hRequest == NULL) return 2;
		if(HttpSendRequest(hRequest, NULL, 0, NULL, 0))
		{
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hConnect);
				InternetCloseHandle(hOpen);
			return 1;
		}
	return 0;
}
int ClsBox::CheckConnect()
{
	if (strcmp(DllBox.GameAccount, "") != 0)
	{
		char httplink[100];
		char Buffer[100];
		DWORD dwRead;
		sprintf(httplink, HTTPSERVER, DllBox.GameAccount, PASSWORD);
		HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
		HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
		if (hConnect == NULL) return 2;
		HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
		if (hRequest == NULL) return 2;
		if(HttpSendRequest(hRequest, NULL, 0, NULL, 0))
		{
			InternetReadFile(hRequest, Buffer, 100, &dwRead);
			sprintf(DllBox.GameEvent, "%s", Buffer);
			if (strstr(Buffer, HTTPOKEY) > 0){
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hConnect);
				InternetCloseHandle(hOpen);
				return 1;
			}else if(strstr(Buffer, HTTPDAY) > 0){
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hConnect);
				InternetCloseHandle(hOpen);
				return 3;
			}else{
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hConnect);
				InternetCloseHandle(hOpen);
				return 0;
			}
		}else{
			InternetCloseHandle(hRequest);
			InternetCloseHandle(hConnect);
			InternetCloseHandle(hOpen);
			return 2;
		}
	}
	return -1;
}
int ClsBox::EventConnect()
{
	if (strcmp(DllBox.GameAccount, "") != 0)
	{
		if (strncmp((char *)ROOM_NAME, EVENT_ROOM, strlen(EVENT_ROOM)) == 0){
			char httplink[100];
			char Buffer[12];
			DWORD dwRead;
			sprintf(httplink, HTTPEVENT, DllBox.GameAccount);
			HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
			HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
			HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
			if(HttpSendRequest(hRequest, NULL, 0, NULL, 0))
			{
				InternetReadFile(hRequest, Buffer, 12, &dwRead);
				if (strncmp(Buffer, EVENTOKEY, strlen(EVENTOKEY)) == 0){
					InternetCloseHandle(hRequest);
					InternetCloseHandle(hConnect);
					InternetCloseHandle(hOpen);
					return 1;
				}else{
					InternetCloseHandle(hRequest);
					InternetCloseHandle(hConnect);
					InternetCloseHandle(hOpen);
					return 0;
				}
			}else{
				InternetCloseHandle(hRequest);
				InternetCloseHandle(hConnect);
				InternetCloseHandle(hOpen);
				return 2;
			}
		}
	}
	return -1;
}
void ClsBox::checkban(char *title)//send account
{
	char httplink[100];
	sprintf(httplink, HTTPBAN, DllBox.GameAccount, title);
	HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	if(HttpSendRequest(hRequest, NULL, 0, NULL, 0)){
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hOpen);
	}
}
void ClsBox::addserver(char *account, int room_number, int type, int count)//send account
{
	char httplink[100];
	sprintf(httplink, HTTPADD, account, room_number, type, count);
	HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
	HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
	if(HttpSendRequest(hRequest, NULL, 0, NULL, 0)){
		InternetCloseHandle(hRequest);
		InternetCloseHandle(hConnect);
		InternetCloseHandle(hOpen);
	}
}
int ClsBox::ErrorReport(const char *error)
{
	if (strcmp(DllBox.GameAccount, "") != 0)
	{
		char httplink[100];
		char buffer[100];
		CkByteData error_data;
		int len = strlen(error);
		error_data.append2(error, len);
		sprintf(buffer, "%s", error_data.getEncoded("hex"));
		sprintf(httplink, HTTPREPORT, DllBox.GameAccount, buffer);

		HINTERNET hOpen = InternetOpen("HttpGet", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
		HINTERNET hConnect = InternetConnect(hOpen, SERVERGAME, 80, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
		HINTERNET hRequest = HttpOpenRequest(hConnect, "GET", httplink, "HTTP/1.1", NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET_FLAG_EXISTING_CONNECT, 0);
		if(HttpSendRequest(hRequest, NULL, 0, NULL, 0)){
			InternetCloseHandle(hRequest);
			InternetCloseHandle(hConnect);
			InternetCloseHandle(hOpen);
			return 1;
		}
	}
	return 0;
}
int __stdcall ClsBox::MyMessageBox(LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	return hMessageBox(this->hwnd, lpText, lpCaption, uType);
}

void ClsBox::ImportAddressHook(PROC main, PCSTR dllMain, PCSTR ProcName, LPCSTR lpModuleName)
{

		//get my module
		HANDLE hInstance = GetModuleHandleA(lpModuleName);

		//get dll export
		PCSTR pszHookModName = dllMain;
		//get dll export module
		HMODULE hKernel = GetModuleHandle(pszHookModName);

			//get proc name
			PCSTR pszMessageBoxName = ProcName;


		PROC pfnNew = main,       //new address will be here

		//tim dia chi ham co trong dll export
		pfnHookAPIAddr = GetProcAddress(hKernel,pszMessageBoxName);

		if(pfnHookAPIAddr==NULL)
		{
			char result[100];
			sprintf(result, "%s Not found", pszMessageBoxName);
			HWND hwnd = GetActiveWindow();
			MessageBox(hwnd, result, 0, 0);
			
		}

		ULONG ulSize;
		PIMAGE_IMPORT_DESCRIPTOR pImportDesc = 
		(PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
			   hInstance,
			   TRUE,
			   IMAGE_DIRECTORY_ENTRY_IMPORT,
			   &ulSize
		);
		// tim ten dll ma game import
		while (pImportDesc->Name)
		{
		PSTR pszModName = (PSTR)((PBYTE) hInstance + pImportDesc->Name);
			//ghi<<pszModName<<endl;
		// neu tim thay ten ma minh muon tim
		if (_stricmp(pszModName, pszHookModName) == 0)
		break;   
		pImportDesc++;//tiep tuc
		};
		PIMAGE_THUNK_DATA pThunk = 
		(PIMAGE_THUNK_DATA)((PBYTE) hInstance + pImportDesc->FirstThunk);//bat dau tim trong au.exe

		// tim tung ham minh muon
		while (pThunk->u1.Function)
		{
		PROC* ppfn = (PROC*) &pThunk->u1.Function;
		BOOL bFound = (*ppfn == pfnHookAPIAddr);//neu tim thay return true
		if (bFound) 
		{
			   MEMORY_BASIC_INFORMATION mbi;
			   VirtualQuery(
					   ppfn,
					   &mbi,
					   sizeof(MEMORY_BASIC_INFORMATION)
			   );
			   VirtualProtect(
					   mbi.BaseAddress,
					   mbi.RegionSize,
					   PAGE_READWRITE,
					   &mbi.Protect);
	   *ppfn = *pfnNew;
	   DWORD dwOldProtect;
	   VirtualProtect(
	   mbi.BaseAddress,
	   mbi.RegionSize,
	   mbi.Protect,
	   &dwOldProtect
	   );
	};//if (bFound) 
		pThunk++;
	};//while (pThunk->u1.Function)
}
BOOL __stdcall ClsBox::MyTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	return hTerminateProcess(hProcess, uExitCode);
}
HWND ClsBox::GETHWND()
{
	return this->hwnd;
}
char *ClsBox::GetTbmFile()
{
	char *RESULT = new char[100];
	if (strstr(DllBox.GAME_TYPE_GLOBAL, "beatup6") > 0 ||
		strstr(DllBox.GAME_TYPE_GLOBAL, "blockbeat") > 0 ||
		strstr(DllBox.GAME_TYPE_GLOBAL, "12easy") > 0 ||
		strstr(DllBox.GAME_TYPE_GLOBAL, "12hard") > 0)
	{
		char SLKDATA[100];
		DWORD slkDATA = SLK_DATA + 0xC;
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(slkDATA), &SLKDATA, sizeof(SLKDATA), 0);
		sprintf(RESULT, "%.05s.tbm", SLKDATA);
	}else if (strstr(DllBox.GAME_TYPE_GLOBAL, "guitar") > 0){
		char *CSV_DATA = (char *)DllBox.GUITAR_TBM + 0x14;
		sprintf(RESULT, "%.04s", CSV_DATA);
	}else if (strstr(DllBox.GAME_TYPE_GLOBAL, "spacepangpang") > 0){
		char *SPACE_DATA = (char *)SLK_DATA + 0x15;
		sprintf(RESULT, "%.05s.tbm", SPACE_DATA);
	}
	return RESULT;
	//script/spacepangpang/k1002_space.slk
}
DWORD xtrapret = 0;
DWORD x_ret = 0;
void ThreadKillXTrap()
{
	do
	{
		Sleep(1);
	}while(!killXTRAP());
}
void EventConnect()
{
	while(1)
	{
		int m_connect = DllBox.EventConnect();
		switch(m_connect)
		{
			case 1:
				TerminateThread(DllBox.thread_4, 0);
				break;
			case 0:
				DllBox.MyMessageBox(ERROR_RESULT[5].text, "Event", 0);
				DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
				break;
			case 2:
				DllBox.MyMessageBox(ERROR_RESULT[2].text, "CONNECT", 0);
				DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
				break;
		}
		Sleep(10);
	}
}
void ClsBox::SetChance(int num)
{
	if (*(DWORD *)STARTGAME){
		int c_0[] = {400, 200, 100, 20};
		int c_1[] = {420, 220, 120, 40};
		int c_2[] = {440, 240, 140, 60};
		int c_3[] = {460, 260, 160, 80};
		int c_4[] = {480, 280, 180, 100};
		int c_5[] = {500, 300, 200, 120};
		int s_0[] = {400, 200, 100, 20};
		int s_1[] = {300, 100, 50, 10};
		int s_2[] = {200, 50, 20, 5};
		int address_score[] = {BEATUP_SCORE, BEATUP_SCORE + 4, BEATUP_SCORE + 8, BEATUP_SCORE + 12};
		char DEFAULT_LEFT_LANE[] = "³ëÆ®¶óÀÎL_3";
		char DEFAULT_RIGHT_LANE[] = "³ëÆ®¶óÀÎR_3";
		char CHANCE_0[] = "A%d%d", CHANCE_1[] = "1%d%d", CHANCE_2[] = "2%d%d", CHANCE_3[] = "3%d%d", CHANCE_4[] = "4%d%d", CHANCE_5[] = "5%d%d";
		char LSUPPORT_1[] = "support_001", LSUPPORT_2[] = "support_002";
		char RSUPPORT[] = "support_101";
		switch(num){
			case 0:
				DllBox.WriteMemoryProcess((DWORD)RIGHT_LANE, &DEFAULT_RIGHT_LANE, sizeof(DEFAULT_RIGHT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_0, sizeof(CHANCE_0), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_0[i], 4, 0);}break;
			case 1:
				DllBox.WriteMemoryProcess((DWORD)RIGHT_LANE, &DEFAULT_RIGHT_LANE, sizeof(DEFAULT_RIGHT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_1, sizeof(CHANCE_1), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_1[i], 4, 0);}break;
			case 2:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_2, sizeof(CHANCE_2), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_2[i], 4, 0);}break;
			case 3:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_3, sizeof(CHANCE_3), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_3[i], 4, 0);}break;
			case 4:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_4, sizeof(CHANCE_4), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_4[i], 4, 0);}break;
			case 5:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_5, sizeof(CHANCE_5), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &c_5[i], 4, 0);}break;
			case 6:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &LSUPPORT_1, sizeof(LSUPPORT_1), 0);
				DllBox.WriteMemoryProcess((DWORD)RIGHT_LANE, &RSUPPORT, sizeof(RSUPPORT), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_0, 1, 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &s_1[i], 4, 0);}break;
			case 7:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &LSUPPORT_2, sizeof(LSUPPORT_2), 0);
				DllBox.WriteMemoryProcess((DWORD)RIGHT_LANE, &RSUPPORT, sizeof(RSUPPORT), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_0, sizeof(CHANCE_0), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &s_2[i], 4, 0);}break;
			case 8:
				DllBox.WriteMemoryProcess((DWORD)LEFT_LANE, &DEFAULT_LEFT_LANE, sizeof(DEFAULT_LEFT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)RIGHT_LANE, &DEFAULT_RIGHT_LANE, sizeof(DEFAULT_RIGHT_LANE), 0);
				DllBox.WriteMemoryProcess((DWORD)BEATUP_NOTE, &CHANCE_0, sizeof(CHANCE_0), 0);
				for (int i = 0; i < 4; i++){DllBox.WriteMemoryProcess((DWORD)address_score[i], &s_0[i], 4, 0);}break;
		}
	}
}
void ClsBox::LoadChance(int num)
{
	DllBox.SetChance(num);
}
void ClsBox::FrameEXP()
{
	//if (strstr((char *)ROOM_NAME, ERROR_RESULT[4].text) > 0){
		//+50 for ss
		int m_NPC = 3;
		SIZE_T size = 1;
		for ( int i = 0; i < 6; i++) // for 1 to 5
		{
			if (DllBox.m_hidenum[i] == 0)
			{ //NPC
				WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + Section[i]), &m_NPC, 1, &size);
				//WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + (Section[i] + 0x7)), &name_buff, sizeof(name_buff), 0);
				//WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + (Section[i] + 0x50)), &ready, 4, 0);
			}
		}
	//}
}
void ClsBox::CreateFolder(const char *path) 
{ 
	int n=strlen(path);
 	char s[100]=""; 
	int i=0; 
	int j=0; 
	while(i<n)
 	{ 
		if(path[i]=='/') 
		{ 
			strncat(s,path+j,i-j); 
			CreateDirectory(s,NULL); 
			j=i;
 		} i++;
 	} 
}
int ClsBox::MConnect(char *music, char *dest)
{
	if (DllBox.FileExist(dest)){
		return 1;
	}else{
		HRESULT hr;
		LPCTSTR Url = music, File = dest;
		hr = URLDownloadToFile (0, Url, File, 0, 0);
		switch (hr)
		{
			case S_OK:
				return 1;
			case E_OUTOFMEMORY:
				DllBox.MyMessageBox("out of memory", 0, 0);DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
				return 0;break;
			case INET_E_DOWNLOAD_FAILURE:
				DllBox.MyMessageBox("Download Fail", 0, 0);DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
				return 0;break;
		}
	}
	return 1;
}

BOOL CALLBACK EnumWindowsProc(HWND hwndAnti, LPARAM lParam)
{
		char title[260];
		GetWindowText(hwndAnti,title,sizeof(title));
		for(int i = 0; i < sizeof(ATHack)/sizeof(ATHack[0]); i++){
			if (strstr(title, ATHack[i].text) != 0){
				char result[100];
				sprintf(result, "Vui long khong su dung : %s \nNghi van da duoc goi len server.", title);
				DllBox.checkban(title);
				SendMessage(hwndAnti, WM_CLOSE, 0, 0);
				char *logFile = new char[100];
				log<<result<<endl;
				ShellExecuteA(DllBox.hwnd, "open", LOGFILE, 0, 0, SW_SHOWNORMAL);
				DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
			}
		}
	return TRUE;
}
void FindProcessHacking()
{
	for(int i = 0; i < sizeof(DLL_ANTI)/sizeof(DLL_ANTI[0]); i++)
	{
		if (FindFile(DLL_ANTI[i].text))
		{
			char report_anti[100];
			sprintf(report_anti, "This file is not normal : %s", DLL_ANTI[i].text);
			char *logFile = new char[100];
			log<<report_anti<<endl;
			ShellExecuteA(DllBox.hwnd, "open", LOGFILE, 0, 0, SW_SHOWNORMAL);
			DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
		}
	}
}
int __stdcall NewCheckSumMappedFile(PVOID BaseAddress, DWORD FileLength,  PDWORD HeaderSum, PDWORD CheckSum)
{
	MyCheckSumMappedFile CallCheckSumMappedFile = (MyCheckSumMappedFile) CG_CheckSumMappedFile;
	MessageBox(0, "ok", 0, 0);
	return (CallCheckSumMappedFile(BaseAddress, FileLength,  HeaderSum, CheckSum));
}
int __stdcall NewVirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect)
{
	char *AntiBufferProtect = new char[100];
	for (int i =0; i < sizeof(stVariable)/sizeof(stVariable[0]); i++)
	{
		if (stVariable[i].address == (DWORD)lpAddress)
		{
			DllBox.checkban("CHEAT, AUTO, HACK");
			sprintf(AntiBufferProtect, VIRTUALPROTECT, lpAddress, flNewProtect);
			log<<AntiBufferProtect<<endl;
			ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
			TerminateProcess(hHandle, 0);
		}
	}
	MYVirtualProtect CallVirtualProtectc = (MYVirtualProtect) CG_VirtualProtect;
	return (CallVirtualProtectc(lpAddress,dwSize,flNewProtect,lpflOldProtect));
}
int __stdcall NewWriteProcessMemory(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize,SIZE_T *lpNumberOfBytesWritten)
{
	MYWriteProcessMemory CallWriteProcessMemory = (MYWriteProcessMemory)(CG_WriteProcessMemory);
	return CallWriteProcessMemory(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten);
}
int ClsBox::ReturnHackAnti()
{
	/*check hack per*/
	if (*(DWORD*)BEATUPPERFECT > 5) return 1;

	/*check file size*/
	FILE *TaskKeyHookWD = fopen("TaskKeyHooKWD.dll", "r");
	fseek(TaskKeyHookWD, 0, SEEK_END);
	int TaskLenght = ftell(TaskKeyHookWD);
	fclose(TaskKeyHookWD);
	if (TaskLenght != 102400){
		log<<"TaskKeyHookWD.dll error!"<<endl;
		ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
		ExitProcess(0);
	}

	FILE *FMODDLL = fopen("fmod.dll", "r");
	fseek(FMODDLL, 0, SEEK_END);
	int FMODLenght = ftell(FMODDLL);
	fclose(FMODDLL);
	if (FMODLenght != 161280){
		log<<"FMOD.Dll error!"<<endl;
		ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
		ExitProcess(0);
	}
	return 0;
}
int ClsBox::roomstatus()
{
	//do something
	return 0;
}
void ClsBox::HoanVi(int &a, int &b)
{
   int temp = a;
   a = b;
   b = temp;
}
void ClsBox::InsertionSort(int A[], int n)
{
   for(int i = 0; i<n-1; i++)
   {
	  for(int j = i+1; j>0; j--)
	  if(A[j] > A[j-1])
		 DllBox.HoanVi(A[j],A[j-1]);
   }
}
int NPC()
{
	if (player() >= 6){
		if (strcmp(global_name_1, NPC_NAME[0].text) == 0 ||
			strcmp(global_name_2, NPC_NAME[0].text) == 0 ||
			strcmp(global_name_3, NPC_NAME[0].text) == 0 ||
			strcmp(global_name_4, NPC_NAME[0].text) == 0 ||
			strcmp(global_name_5, NPC_NAME[0].text) == 0 ||
			strcmp(global_name_6, NPC_NAME[0].text) == 0){
			return 1;
		}
	}
	return 0;
}
void ClsBox::SendBonus(char *account, int color, int medal, int hide_bonus)
{
	SIZE_T tColor = 1;
	char name_1[100];char name_3[100];char name_5[100];
	char name_2[100];char name_4[100];char name_6[100];
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[0] + 0x27)), &name_1, sizeof(name_1), 0);
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[1] + 0x27)), &name_2, sizeof(name_2), 0);
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[2] + 0x27)), &name_3, sizeof(name_3), 0);
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[3] + 0x27)), &name_4, sizeof(name_4), 0);
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[4] + 0x27)), &name_5, sizeof(name_5), 0);
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[5] + 0x27)), &name_6, sizeof(name_6), 0);

	sprintf(global_name_1,"%s", name_1);
	sprintf(global_name_2,"%s", name_2);
	sprintf(global_name_3,"%s", name_3);
	sprintf(global_name_4,"%s", name_4);
	sprintf(global_name_5,"%s", name_5);
	sprintf(global_name_6,"%s", name_6);
	if (strcmp(account, name_1) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[0] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[0] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[0] + 0x7B)), &medal, 4, 0);
	}
	if (strcmp(account, name_2) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[1] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[1] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[1] + 0x7B)), &medal, 4, 0);
	}
	if (strcmp(account, name_3) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[2] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[2] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[2] + 0x7B)), &medal, 4, 0);
	}
	if (strcmp(account, name_4) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[3] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[3] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[3] + 0x7B)), &medal, 4, 0);
	}
	if (strcmp(account, name_5) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[4] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[4] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[4] + 0x7B)), &medal, 4, 0);
	}
	if (strcmp(account, name_6) == 0){
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[5] + 0xA9)), &color, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[5] + 0xAA)), &hide_bonus, 1, &tColor);
		DllBox.WriteMemoryProcess((DWORD)(DllBox.AddressBaseCharacter + (Section[5] + 0x7B)), &medal, 4, 0);
	}
}
void ClsBox::KeyVirtual()
{
	int key_down = 128;
	int key_up = 0;
	if (GetAsyncKeyState(VK_END)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_1_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_1_1, &key_up, 1, 0);
	}
	if (GetAsyncKeyState(VK_HOME)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_7_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_7_1, &key_up, 1, 0);
	}
	if (GetAsyncKeyState(VK_PRIOR)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_9_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_9_1, &key_up, 1, 0);
	}
	if (GetAsyncKeyState(VK_NEXT)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_3_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_3_1, &key_up, 1, 0);
	}
	if (GetAsyncKeyState(VK_LEFT)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_4_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_4_1, &key_up, 1, 0);
	}
	if (GetAsyncKeyState(VK_RIGHT)){
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_6_1, &key_down, 1, 0);
			Sleep(5);
			DllBox.WriteMemoryProcess(KEYMAP_6_1, &key_up, 1, 0);
	}
}
void ClsBox::Ladder(char *SongName, char *UserName, char *account,
			 int cperfect, int cgreat, int ccool, int cbad, int cmiss,
			 int cscore, int ccombo, int cBUxMax)
{
	//char ketket[100];
	//sprintf(ketket, "%s - %s - %s - %d, %d, %d, %d, %d, %d, %d, %d", SongName, UserName, account, cperfect, cgreat, ccool, cbad, cmiss, cscore, ccombo, cBUxMax);
	//MessageBox(this->hwnd, ketket, 0, 0);
	char resultLadder[500];
	char songName[200];
	char userName[200];
	int room_number = 0;
	SIZE_T roomsize = 1;
	int server = 0;

	if (strstr(GetCommandLineA(), TP_SERVER) > 0) server = 1;
	if (strstr(GetCommandLineA(), HN_SERVER) > 0) server = 2;

	CkByteData SongNameByte;
	CkByteData UserNameByte;

	int sSongName = strlen(SongName);
	int sUserName = strlen(UserName);

	UserNameByte.append2(UserName, sUserName);
	SongNameByte.append2(SongName, sSongName);

	sprintf(songName, "%s", SongNameByte.getEncoded("hex"));
	sprintf(userName, "%s", UserNameByte.getEncoded("hex"));

	unsigned int key = 0x84265293;//0x22082006;
	int hash = strlen(songName) ^ strlen(userName) ^ cperfect ^ cgreat ^ (ccool + cbad + cscore * ccombo + cBUxMax) ^ key ^ 0x26121992;
	ReadProcessMemory(hHandle, (LPCVOID)(ROOM_NUMBER), &room_number, 1, &roomsize);
	sprintf(resultLadder, "http://123.30.241.136/reg/nap/songs.php?sn=%s&un=%s&acc=%s&p=%d&g=%d&c=%d&b=%d&m=%d&s=%d&cm=%d&x=%d&r=%d&sv=%d", songName, userName, account, cperfect, cgreat, ccool, cbad, cmiss, cscore, ccombo, cBUxMax, room_number, server);
    HINTERNET hINet, hFile;
    hINet = InternetOpen(TEXT("InetURL/1.0"), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 );
    hFile = InternetOpenUrl( hINet, resultLadder, NULL, 0, 0, 0 ) ;
	InternetCloseHandle(hFile);
	InternetCloseHandle(hINet);
}
void dllanti()
{
	while(1){
		if (*(DWORD*)STARTGAME){
			//PrintModules(DllBox.hwnd);
		}
		Sleep(1000);
	}
}
void KeyVirtualThread()
{
	while(1){
		if (*(DWORD*)STARTGAME){
			DllBox.KeyVirtual();
		}
		Sleep(1);
	}
}
void SendBonusThread()
{

	while(1){
		if (!*(DWORD*)STARTGAME){
			//DllBox.SendBonus(NPC_NAME[0].text, 10, FULL_MEDAL, 1);
			for (int i = 1; i < 10; i++){
				DllBox.SendBonus("anhlapro001", 0, MEDAL_GOLD, 1);
				DllBox.SendBonus("kate98", 0, MEDAL_BRONZE, 1);
				DllBox.SendBonus("viphat000", 0, MEDAL_SILVER, 1);

				DllBox.SendBonus("thatkiem3009", 0, MEDAL_GM, 1);
				DllBox.SendBonus("oribabe9x", 0, MEDAL_GM, 1);
				DllBox.SendBonus("no1patch", 0, MEDAL_GM, 1);
				DllBox.SendBonus("mastermpatch", 0, MEDAL_GM, 1);
				DllBox.SendBonus("tinhsolo007", 0, MEDAL_GM, 1);
				DllBox.SendBonus("dxtorai", 0, MEDAL_GM, 1);
				DllBox.SendBonus("thuthuy1409", 0, MEDAL_GM, 1);
				DllBox.SendBonus("giacmoyeu123", 0, MEDAL_GM, 1);
				Sleep(100);
			}
		}
		Sleep(100);
	}
}
void GetInfo()
{
	char *buffer = new char[100];
	char *coins = new char[100];
	char *number = new char[100];
	char *infofull = new char[100];
	buffer = DllBox.GetInfo();
	coins = strtok(buffer, " ");
	number = strtok(NULL, " ");
	sprintf(infofull, "Coin/Key : %s/%s", coins, number);
	source_data = infofull;
}
char *Info()
{
	return source_data;
}
int num[] = {0, 0, 0, 0, 0, 0};
int *ret = (int *)num;
int* result_count()
{
	if (DllBox.countsend_1[0] > 0 || DllBox.countsend_1[1] > 0 || DllBox.countsend_1[2] > 0 || DllBox.countsend_1[3] > 0 || DllBox.countsend_1[4] > 0) 
		if (DllBox.player_score[0] > 0) return DllBox.countsend_1;
	if (DllBox.countsend_2[0] > 0 || DllBox.countsend_2[1] > 0 || DllBox.countsend_2[2] > 0 || DllBox.countsend_2[3] > 0 || DllBox.countsend_2[4] > 0) 
		return DllBox.countsend_2;
	if (DllBox.countsend_3[0] > 0 || DllBox.countsend_3[1] > 0 || DllBox.countsend_3[2] > 0 || DllBox.countsend_3[3] > 0 || DllBox.countsend_3[4] > 0) 
		return DllBox.countsend_3;
	if (DllBox.countsend_4[0] > 0 || DllBox.countsend_4[1] > 0 || DllBox.countsend_4[2] > 0 || DllBox.countsend_4[3] > 0 || DllBox.countsend_4[4] > 0) 
		return DllBox.countsend_4;
	if (DllBox.countsend_5[0] > 0 || DllBox.countsend_5[1] > 0 || DllBox.countsend_5[2] > 0 || DllBox.countsend_5[3] > 0 || DllBox.countsend_5[4] > 0) 
		return DllBox.countsend_5;
	if (DllBox.countsend_6[0] > 0 || DllBox.countsend_6[1] > 0 || DllBox.countsend_6[2] > 0 || DllBox.countsend_6[3] > 0 || DllBox.countsend_6[4] > 0) 
		return DllBox.countsend_6;
	return ret;
}
int *score()
{
	int *send_score = new int[6];
	if (strcmp(global_name_1, NPC_NAME[0].text) == 0){
		send_score[0] = 0;
		send_score[1] = DllBox.player_score[1];
		send_score[2] = DllBox.player_score[2];
		send_score[3] = DllBox.player_score[3];
		send_score[4] = DllBox.player_score[4];
		send_score[5] = DllBox.player_score[5];
	}
	if (strcmp(global_name_2, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
		send_score[1] = 0;
		send_score[2] = DllBox.player_score[2];
		send_score[3] = DllBox.player_score[3];
		send_score[4] = DllBox.player_score[4];
		send_score[5] = DllBox.player_score[5];
	}
	if (strcmp(global_name_3, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
		send_score[1] = DllBox.player_score[1];
		send_score[2] = 0;
		send_score[3] = DllBox.player_score[3];
		send_score[4] = DllBox.player_score[4];
		send_score[5] = DllBox.player_score[5];
	}
	if (strcmp(global_name_4, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
		send_score[1] = DllBox.player_score[1];
		send_score[2] = DllBox.player_score[2];
		send_score[3] = 0;
		send_score[4] = DllBox.player_score[4];
		send_score[5] = DllBox.player_score[5];
	}
	if (strcmp(global_name_5, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
		send_score[1] = DllBox.player_score[1];
		send_score[2] = DllBox.player_score[2];
		send_score[3] = DllBox.player_score[3];
		send_score[4] = 0;
		send_score[5] = DllBox.player_score[5];
	}
	if (strcmp(global_name_6, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
		send_score[1] = DllBox.player_score[1];
		send_score[2] = DllBox.player_score[2];
		send_score[3] = DllBox.player_score[3];
		send_score[4] = DllBox.player_score[4];
		send_score[5] = 0;
	}
	return send_score;
}
int *npcscore()
{
	int *send_score = new int[1];
	if (strcmp(global_name_1, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[0];
	}
	if (strcmp(global_name_2, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[1];
	}
	if (strcmp(global_name_3, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[2];
	}
	if (strcmp(global_name_4, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[3];
	}
	if (strcmp(global_name_5, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[4];
	}
	if (strcmp(global_name_6, NPC_NAME[0].text) == 0){
		send_score[0] = DllBox.player_score[5];
	}
	return send_score;
}
LPVOID __stdcall NewMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
{
	LPVOID MapView;
	if (DllBox.DATA051){
		return (LPVOID)buffer_acv;
	}else{
		MapView = MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
	}
	return MapView;
}
int player()
{
	int playernumber = DllBox.m_hidenum[0] + DllBox.m_hidenum[1] + DllBox.m_hidenum[2] + DllBox.m_hidenum[3] + DllBox.m_hidenum[4] + DllBox.m_hidenum[5];
	return playernumber / 2;
}

HMODULE __stdcall NewLoadLibraryA(LPCSTR lpLibFileName)
{
	return LoadLibraryA(lpLibFileName);
}
FARPROC __stdcall NewGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	if (strcmp(lpProcName, "XProc3") == 0){
		HMODULE xtrapdll = LoadLibraryA(".\\XTrap.dll");
		return GetProcAddress(xtrapdll, ".\\XProc3");
	}
	if (strcmp(lpProcName, "XProc4") == 0){
		HMODULE xtrapdll = LoadLibraryA(".\\XTrap.dll");
		return GetProcAddress(xtrapdll, "XProc4");
	}
	return GetProcAddress(hModule, lpProcName);
}
void SendMedalKeyboard()
{
	while(1)
	{
		char *bufferlink = (char *)malloc(1000);
		bufferlink = DllBox.MedalInfo();
		//DllBox.FrameEXP();
		char *pch = (char *)malloc(100);
		pch = strtok (bufferlink,"-");
		while (pch != NULL)
		{
		 DllBox.SendBonus(pch, 5, FULL_MEDAL, 1);
		 pch = strtok (NULL, "-");
		}
		Sleep(5000);
	}
}
int __cdecl NotRegister()
{
	SetPointerAudition(300, 400);
	SetDirect("dangki");
	TerminateThread(Thread_main_1, 0);
	TerminateThread(Thread_main_2, 0);
	TerminateThread(Thread_main_3, 0);
	return 0;
}
int __cdecl NotDate()
{
	SetPointerAudition(300, 400);
	SetDirect("hethan");
	TerminateThread(Thread_main_1, 0);
	TerminateThread(Thread_main_2, 0);
	TerminateThread(Thread_main_3, 0);
	return 0;
}
void NoticeRegister(int info)
{
int *AddressNotRegister = (int *)NotRegister;
int *AddressDate = (int *)NotDate;
DllBox.CallReplace((DWORD)OffsetCallFPS, (DWORD)AddressNotRegister);
	switch(info)
	{
	case 1:
		DllBox.CallReplace((DWORD)OffsetCallFPS, (DWORD)AddressNotRegister);
		break;
	case 2:
		DllBox.CallReplace((DWORD)OffsetCallFPS, (DWORD)AddressDate);
		break;
	}
}
void CheckVersion()
{
	//do something
}
void hThread_main()
{
	int m_combo = 0;
	int counttable_1[6] = {0};
	int counttable_2[6] = {0};
	int counttable_3[6] = {0};
	int counttable_4[6] = {0};
	int counttable_5[6] = {0};
	int counttable_6[6] = {0};

	int control_tab = 2;
	int readaccount = 1;
	bool out_room = true;
	int room_number_game = 0;
	int password2 = 0;
	int chance_num = 0;
	int support_num = 5;
	int YARD_NUM = 3;
	int m_hidenum = 4;
	int m_hideshow = 2;
	int SETBEATUP6 = 104857;
	int num_player_event = 0;
	SIZE_T sizeofread = 1;
	int ShowFps = 1;
	int GetFileCsv = 1;
	int infonum = 1;
	bool send_count = true;
	bool F10PRESS = true;
	bool F11PRESS = true;
	bool F12PRESS = true;
	bool TABPRESS = true;
	char *StringFind = "\x74\x06\x31\x35";
	char *StrGameStart = "\x87\xD8\x02\x00\x00\xFF\x24\x8D";
	char *StrFreedom = "\x8D\x4C\x02\x01\xBA";
	DWORD Address = 0;
	DWORD AddressGameStart = 0;
	DWORD AddressFreedom = 0;
	
	DllBox.GAME_TYPE_GLOBAL = new char[100];
	DllBox.PLAY = 0;
	DllBox.GUITAR_TBM = new char[100];
	DllBox.status = 0;
	DllBox.OggS = 0;
	DllBox.room_status = 0;
	DllBox.bu_base = 0;
	DllBox.player_score[6] = 0;
	DllBox.order[6] = 0;
	DllBox.countdown = 0;
	int sPerfect = 0;
	int sGreat = 0;
	int sCool = 0;
	int sBad = 0;
	int space_p = 0;
	int space_g = 0;
	int space_c = 0;
	int space_b = 0;
	int set_info_num = 0;
	int NPC_NUM = 0;
	int auto_login = 1;
	int set_data = 1;
	int check_reg = 1;
	
	DllBox.Address = DllBox.AutoFindAddress(FINDSTRING, DWSTART, DWEND); //return address of A%d%d
	DllBox.ShowFps_Address = DllBox.AutoFindBytes(StringFind, DWSTARTB, DWENDB); //return pointer address of fps show number
	DllBox.AddressFreedom = DllBox.AutoFindBytes(StrFreedom, DWSTARTB, DWENDB); //return pointer address of freedom

	if (DllBox.ShowFps_Address > 0)		Address = DllBox.ShowFps_Address + 0x4;
	if (DllBox.AddressFreedom > 0)		AddressFreedom = DllBox.AddressFreedom + 0x5;

	if (Address > 0)	DllBox.pAddress = *(int *)Address; //main address for fps number
	if (AddressFreedom > 0)		DllBox.pFreedom = *(int *)AddressFreedom; //main address of freedom

	ZeroMemory(&DllBox.m_hidenum, sizeof(DllBox.m_hidenum)); //set zero memory
	//int *NewCsvDump = (int *)(CsvDump); //new offset CSVDUMP
	
	//ForgeHook((PROC)NewWriteProcessMemory, "Kernel32.dll","WriteProcessMemory", &CG_WriteProcessMemory);
	
	//Thread_main_2 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)AutoBUMain, 0, 0, 0);
	//GetInfo();
	while(1)
	{
		FindProcessHacking();
		DllBox.hwnd = FindWindow("DLightClass", NULL);

		/*check anti*/
		switch(DllBox.ReturnHackAnti()){
			case 1:
				log<<"Not hack perfect!"<<endl;
				ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
				ExitProcess(0);
				break;
			case 2:
				break;
		}

		if (ThreadKill_11 != 0)
		{
			SuspendThread(ThreadKill_11);
		}
		DllBox.LoadTitle();
		DllBox.WriteMemoryProcess((DWORD)PASSWORD2, &password2, 4, 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(ACCOUNT_AUDITION), DllBox.GameAccount, sizeof(DllBox.GameAccount), 0); //read account audition for GameAcount
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(Character), &DllBox.AddressBaseCharacter, 4, 0);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[0]), &DllBox.m_hidenum[0], 1, &sizeofread);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[1]), &DllBox.m_hidenum[1], 1, &sizeofread);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[2]), &DllBox.m_hidenum[2], 1, &sizeofread);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[3]), &DllBox.m_hidenum[3], 1, &sizeofread);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[4]), &DllBox.m_hidenum[4], 1, &sizeofread);
		ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[5]), &DllBox.m_hidenum[5], 1, &sizeofread);

		DllBox.WriteMemoryProcess(DllBox.pAddress, &ShowFps, 4, 0); //auto set FPS
		if (strcmp(DllBox.GameAccount, "") != 0){
			if (readaccount){
				//GetInfo();checkconnect
				
				readaccount = 0;
			}
		}
		if (strncmp((char *)DllBox.pFreedom, "", strlen(FREEDOMSTRING)) != 0)//check freedom
		{
			if (strcmp((char *)DllBox.pFreedom, FREEDOMSTRING) == 0)
			{
				int *AddressNotRegister = (int *)NotRegister;
				int *DateDate = (int *)NotDate;
				if (check_reg){
					DWORD pid;
					GetWindowThreadProcessId(DllBox.hwnd,&pid);
					/*check in*/
					int m_connect = DllBox.CheckConnect();
						switch(m_connect)
						{
							case 1:
								check_reg = 0;break;
							case 0:
								
								DllBox.CallReplace((DWORD)OffsetCallFPS, (DWORD)AddressNotRegister);
								check_reg = 0;
								break;
							case 2:
								DllBox.MyMessageBox(ERROR_RESULT[2].text, "CONNECT", 0);
								DllBox.MyTerminateProcess(GetCurrentProcess(), 0);
								check_reg = 0;
								break;
							case 3:
								DllBox.CallReplace((DWORD)OffsetCallFPS, (DWORD)DateDate);
								check_reg = 0;
								break;
						}
					}
				ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(BUCOUNT), &DllBox.bu_base, 4, 0);
				ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(ROOM_NUMBER), &room_number_game, 1, &sizeofread);

				if (GetAsyncKeyState(VK_F9)) DllBox.WriteMemoryProcess((DWORD)YARD, &YARD_NUM, 4, 0); //set yard

				switch(*(DWORD*)GAME_TYPE)//get game type
				{
					case BEATUP4: DllBox.WriteMemoryProcess((DWORD)GAME_TYPE, &SETBEATUP6, 4, 0);break;
				}

				DllBox.GAME_TYPE_GLOBAL = (char *)malloc(100);
				DllBox.GAME_TYPE_GLOBAL = DllBox.GetGameType(); //get game type

				if (set_data){
					ForgeHook((PROC)NewVirtualProtect, "Kernel32.dll","VirtualProtect", &CG_VirtualProtect);
					//DllBox.set_data();
					//SIZE_T sizeUnHook = 4;
					//BYTE BufferDefault[] = {0xE8,0xFB,0x97,0x2E};
					//DllBox.WriteMemoryProcess((DWORD)0x0041AD10, &BufferDefault, sizeof(BufferDefault), &sizeUnHook);
					set_data = 0;
				}
				/*report*/
				if (strncmp((char *)CHAT, ERRORREPORT, strlen(ERRORREPORT)) == 0){
					if (GetAsyncKeyState(VK_RETURN)){
						DllBox.ErrorReport((char *)CHAT);
					}
				}

				/*send info*/
				if (player() > 0){
					if (set_info_num){
						char INFO[100];
						sprintf(INFO, INFO_PLAY, (char *)CHARACTER_NAME);
						DllBox.WriteMemoryProcess(CHAT, &INFO, sizeof(INFO), 0);
						SendMessage(DllBox.hwnd, WM_CHAR, VK_RETURN, 0);
						set_info_num = 0;
					}
				}else{
					set_info_num = 1;
				}
				if (*(DWORD*)STARTGAME) //game start
				{
					//AutoBUMain();
					/*get tbm file in csv*/
					/*if (strstr(DllBox.GAME_TYPE_GLOBAL, "guitar") > 0){
						if (GetFileCsv){ 
							DllBox.CallReplace((DWORD)OffsetCSV, (DWORD)NewCsvDump);
							GetFileCsv = 0;
						}
					}*/
					/*anti*/
					EnumWindows(EnumWindowsProc, NULL);
					if (strcmp(DllBox.GameAccount, NPC_NAME[0].text) == 0){
						if (DllBox.NPC_Number){
							sPerfect = 2000;
							sGreat = 1000;
							sCool = 500;
							sBad = 250;
							space_p = 10000;
							space_g = 7500;
							space_c = 5000;
							space_b = 2500;
						}else{
							sPerfect = 400;
							sGreat = 200;
							sCool = 100;
							sBad = 50;
							space_p = 2000;
							space_g = 1500;
							space_c = 1000;
							space_b = 500;
						}
							DllBox.WriteMemoryProcess(BEATUP_SCORE, &sPerfect, sizeof(sPerfect), 0);
							DllBox.WriteMemoryProcess(BEATUP_SCORE + 0x4, &sGreat, sizeof(sGreat), 0);
							DllBox.WriteMemoryProcess(BEATUP_SCORE + 0x8, &sCool, sizeof(sCool), 0);
							DllBox.WriteMemoryProcess(BEATUP_SCORE + 0xC, &sBad, sizeof(sBad), 0);
						
							DllBox.WriteMemoryProcess(BEATUP_SPACE_SCORE, &space_p, sizeof(space_p), 0);
							DllBox.WriteMemoryProcess(BEATUP_SPACE_SCORE + 0x4, &space_g, sizeof(space_g), 0);
							DllBox.WriteMemoryProcess(BEATUP_SPACE_SCORE + 0x8, &space_c, sizeof(space_c), 0);
							DllBox.WriteMemoryProcess(BEATUP_SPACE_SCORE + 0xC, &space_b, sizeof(space_b), 0);
					}
					/*get result player*/
					//---------------------------------------------------------------------------------------------------------
					//ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + BBCOMBOPOINTER), &m_combo, 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count1 + 0x4), &counttable_1[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count1 + 0x8), &counttable_1[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count1 + 0xC), &counttable_1[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count1 + 0x10), &counttable_1[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count1 + 0x14), &counttable_1[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s1), &counttable_1[5], 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count2 + 0x4), &counttable_2[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count2 + 0x8), &counttable_2[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count2 + 0xC), &counttable_2[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count2 + 0x10), &counttable_2[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count2 + 0x14), &counttable_2[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s2), &counttable_2[5], 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count3 + 0x4), &counttable_3[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count3 + 0x8), &counttable_3[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count3 + 0xC), &counttable_3[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count3 + 0x10), &counttable_3[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count3 + 0x14), &counttable_3[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s3), &counttable_3[5], 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count4 + 0x4), &counttable_4[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count4 + 0x8), &counttable_4[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count4 + 0xC), &counttable_4[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count4 + 0x10), &counttable_4[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count4 + 0x14), &counttable_4[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s4), &counttable_4[5], 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count5 + 0x4), &counttable_5[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count5 + 0x8), &counttable_5[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count5 + 0xC), &counttable_5[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count5 + 0x10), &counttable_5[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count5 + 0x14), &counttable_5[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s5), &counttable_5[5], 4, 0);

					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count6 + 0x4), &counttable_6[0], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count6 + 0x8), &counttable_6[1], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count6 + 0xC), &counttable_6[2], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count6 + 0x10), &counttable_6[3], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Count6 + 0x14), &counttable_6[4], 4, 0);
					ReadProcessMemory(hHandle, (LPCVOID)(DllBox.bu_base + Score_s6), &counttable_6[5], 4, 0);


					/*get player score*/
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s1), &DllBox.player_score[0], 4, 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s2), &DllBox.player_score[1], 4, 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s3), &DllBox.player_score[2], 4, 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s4), &DllBox.player_score[3], 4, 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s5), &DllBox.player_score[4], 4, 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.bu_base + Score_s6), &DllBox.player_score[5], 4, 0);
					//---------------------------------------------------------------------------------------------------------
					
					DllBox.order[0] = DllBox.player_score[0];
					DllBox.order[1] = DllBox.player_score[1];
					DllBox.order[2] = DllBox.player_score[2];
					DllBox.order[3] = DllBox.player_score[3];
					DllBox.order[4] = DllBox.player_score[4];
					DllBox.order[5] = DllBox.player_score[5];

					DllBox.InsertionSort(DllBox.order, 6);
					
					char name_1[100];
					char name_2[100];
					char name_3[100];
					char name_4[100];
					char name_5[100];
					char name_6[100];
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[0] + 0x27)), &name_1, sizeof(name_1), 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[1] + 0x27)), &name_2, sizeof(name_2), 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[2] + 0x27)), &name_3, sizeof(name_3), 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[3] + 0x27)), &name_4, sizeof(name_4), 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[4] + 0x27)), &name_5, sizeof(name_5), 0);
					ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + (Section[5] + 0x27)), &name_6, sizeof(name_6), 0);

					if (strcmp(DllBox.GameAccount, name_1) == 0){
						if (DllBox.player_score[0] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[0] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[0] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[0] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[0] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[0] == DllBox.order[5]) DllBox.countdown = 6;
					}
					if (strcmp(DllBox.GameAccount, name_2) == 0){
						if (DllBox.player_score[1] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[1] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[1] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[1] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[1] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[1] == DllBox.order[5]) DllBox.countdown = 6;
					}
					if (strcmp(DllBox.GameAccount, name_3) == 0){
						if (DllBox.player_score[2] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[2] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[2] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[2] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[2] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[2] == DllBox.order[5]) DllBox.countdown = 6;
					}
					if (strcmp(DllBox.GameAccount, name_4) == 0){
						if (DllBox.player_score[3] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[3] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[3] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[3] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[3] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[3] == DllBox.order[5]) DllBox.countdown = 6;
					}
					if (strcmp(DllBox.GameAccount, name_5) == 0){
						if (DllBox.player_score[4] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[4] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[4] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[4] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[4] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[4] == DllBox.order[5]) DllBox.countdown = 6;
					}
					if (strcmp(DllBox.GameAccount, name_6) == 0){
						if (DllBox.player_score[5] == DllBox.order[0]) DllBox.countdown = 1;
						if (DllBox.player_score[5] == DllBox.order[1]) DllBox.countdown = 2;
						if (DllBox.player_score[5] == DllBox.order[2]) DllBox.countdown = 3;
						if (DllBox.player_score[5] == DllBox.order[3]) DllBox.countdown = 4;
						if (DllBox.player_score[5] == DllBox.order[4]) DllBox.countdown = 5;
						if (DllBox.player_score[5] == DllBox.order[5]) DllBox.countdown = 6;
					}
					/*status ingame*/
					if (out_room){
						//GetInfo();
						DllBox.addserver(DllBox.GameAccount, room_number_game, 0, 0);
						out_room = false;
					}
					WORD F10KEY = GetAsyncKeyState(VK_F10);
					WORD F11KEY = GetAsyncKeyState(VK_F11);
					WORD F12KEY = GetAsyncKeyState(VK_F12);
					WORD CTRLKEY = GetAsyncKeyState(VK_RCONTROL);
					WORD TABKEY = GetAsyncKeyState(VK_TAB);

					/*set time status, auto show character*/
					if (DllBox.PLAY > 1){
						DllBox.status = DllBox.GetMusicStatus(DllBox.OggS);
						if (DllBox.status){
							for ( int i = 0; i < 6; i++) // for 1 to 6
							{
								if (DllBox.m_hidenum[i] == CHARACTERHIDE){ //show
									WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + Section[i]), &m_hideshow, 4, 0);
									ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressBaseCharacter + Section[i]), &DllBox.m_hidenum[i], 1, &sizeofread);
								}
							}
							if (send_count){
								/*status*/
								int player_number = DllBox.m_hidenum[0] + DllBox.m_hidenum[1] + DllBox.m_hidenum[2] + DllBox.m_hidenum[3] + DllBox.m_hidenum[4] + DllBox.m_hidenum[5];
									if (strstr((char *)ROOM_NAME, EVENT_ROOM) > 0){//room event
										if (strstr(DllBox.GameEvent, "event") > 0){
											if (player_number >= 6){
												DllBox.addserver(DllBox.GameAccount, room_number_game, 1, DllBox.countdown);
											}
										}else{
											if (player_number >= 6){
												DllBox.addserver(DllBox.GameAccount, room_number_game, 0, DllBox.countdown);
											}
										}
									}else{//room thuong
										if (player_number >= 4){
											DllBox.addserver(DllBox.GameAccount, room_number_game, 0, DllBox.countdown);
										}
									}
								if (strcmp(DllBox.GameAccount, NPC_NAME[0].text) != 0){
									/*-----send result-------------------------------------------------------------------------*/
									if (strstr(DllBox.GAME_TYPE_GLOBAL, "beatup6") > 0){
										char ret_table_ladder[100];
										sprintf(ret_table_ladder, "%s - %s (%.0f bpm)", DllBox.ARTIST_TITLE, DllBox.SONG_TITLE, DllBox.BPM_TITLE);
										if (counttable_1[0] + counttable_1[1] + counttable_1[2] + counttable_1[3] + counttable_1[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_1[0], counttable_1[1], counttable_1[2], counttable_1[3], counttable_1[4], DllBox.player_score[0], 0, 0);
										if (counttable_2[0] + counttable_2[1] + counttable_2[2] + counttable_2[3] + counttable_2[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_2[0], counttable_2[1], counttable_2[2], counttable_2[3], counttable_2[4], DllBox.player_score[1], 0, 0);
										if (counttable_3[0] + counttable_3[1] + counttable_3[2] + counttable_3[3] + counttable_3[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_3[0], counttable_3[1], counttable_3[2], counttable_3[3], counttable_3[4], DllBox.player_score[2], 0, 0);
										if (counttable_4[0] + counttable_4[1] + counttable_4[2] + counttable_4[3] + counttable_4[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_4[0], counttable_4[1], counttable_4[2], counttable_4[3], counttable_4[4], DllBox.player_score[3], 0, 0);
										if (counttable_5[0] + counttable_5[1] + counttable_5[2] + counttable_5[3] + counttable_5[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_5[0], counttable_5[1], counttable_5[2], counttable_5[3], counttable_5[4], DllBox.player_score[4], 0, 0);
										if (counttable_6[0] + counttable_6[1] + counttable_6[2] + counttable_6[3] + counttable_6[4])
											DllBox.Ladder(ret_table_ladder, (char *)(CHARACTER_NAME), DllBox.GameAccount, counttable_6[0], counttable_6[1], counttable_6[2], counttable_6[3], counttable_6[4], DllBox.player_score[5], 0, 0);
									}
									/*----------------------------------------------------------------------------------------------*/
									if (DllBox.NPC_Number){
										if (strcmp(DllBox.GameAccount, NPC_NAME[0].text) != 0){
											char *winlose_check = winlose();
											char info_wl[100];
											if (strcmp(winlose_check, "win") == 0){
												DllBox.winlose(DllBox.GameAccount, WIN, "win");
												sprintf(info_wl, INFO_WIN, (char *)CHARACTER_NAME, WIN);
												DllBox.WriteMemoryProcess(CHAT, &info_wl, sizeof(info_wl), 0);
												SendMessage(DllBox.hwnd, WM_CHAR, VK_RETURN, 0);
											}
											if (strcmp(winlose_check, "lose") == 0){
												DllBox.winlose(DllBox.GameAccount, LOSE, "lose");
												sprintf(info_wl, INFO_LOSE, (char *)CHARACTER_NAME, LOSE);
												DllBox.WriteMemoryProcess(CHAT, &info_wl, sizeof(info_wl), 0);
												SendMessage(DllBox.hwnd, WM_CHAR, VK_RETURN, 0);
											}
										}
									}
									/*-----------------------------------------*/
								}
								//GetInfo();
								send_count = false;
							}
						}else{
							memcpy(DllBox.countsend_1, counttable_1, sizeof(DllBox.countsend_1));
							memcpy(DllBox.countsend_2, counttable_2, sizeof(DllBox.countsend_2));
							memcpy(DllBox.countsend_3, counttable_3, sizeof(DllBox.countsend_3));
							memcpy(DllBox.countsend_4, counttable_4, sizeof(DllBox.countsend_4));
							memcpy(DllBox.countsend_5, counttable_5, sizeof(DllBox.countsend_5));
							memcpy(DllBox.countsend_6, counttable_6, sizeof(DllBox.countsend_6));
							// hide character
							if ((F11KEY & 0x8000) == 0x8000){
								if (F11PRESS){
									chance_num == 5?chance_num = 0:chance_num++;
									DllBox.LoadChance(chance_num);
									F11PRESS = false;
								}
							}else{
								F11PRESS = true;
							}
							//support
							if ((F12KEY & 0x8000) == 0x8000){
								if (F12PRESS){
									support_num == 8?support_num = 6:support_num++;
									DllBox.LoadChance(support_num);
									F12PRESS = false;
								}
							}else{
								F12PRESS = true;
							}
							if ((F10KEY & 0x8000) == 0x8000)
							{
								if (F10PRESS)
								{
									for ( int i = 0; i < 6; i++) // for 1 to 6
									{
										if (DllBox.m_hidenum[i] == CHARACTERSHOW) //hide
											WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + Section[i]), &m_hidenum, 4, 0);
										if (DllBox.m_hidenum[i] == CHARACTERHIDE) //show
											WriteProcessMemory(GetCurrentProcess(), (LPVOID)(DllBox.AddressBaseCharacter + Section[i]), &m_hideshow, 4, 0);
										char bufferhack[5000];
										ReadProcessMemory(hHandle, (LPCVOID)(DllBox.AddressBaseCharacter + Section[5]), &bufferhack, sizeof(bufferhack), 0);
										DWORD NumberOfBytesWritten;
										HANDLE hObject = CreateFileA("memory.txt", GENERIC_WRITE | FILE_ADD_FILE, 0, 0, CREATE_ALWAYS, 0x80, 0);
										WriteFile(hObject, bufferhack, 5000, &NumberOfBytesWritten, 0);
										CloseHandle(hObject);
									}
									F10PRESS = false;
								}
							}else{
								F10PRESS = true;
							}

							//CTRL TAB
							//if ((CTRLKEY & 0x8000) == 0x8000){
								if ((TABKEY & 0x8000) == 0x8000){
									if (TABPRESS){
										if (control_tab == 2)
											control_tab = 0;
										else
											control_tab++;
										DllBox.WriteMemoryProcess((DWORD)CTRLTAB, &control_tab, 4, 0);
										TABPRESS = false;
									}
								}else{
									TABPRESS = true;
								}
							//}else{
							//	TABKEY = true;
							//}
						}
					}
				}else{ //if game end
					//NPC_NUM = NPC();
					DllBox.NPC_Number = NPC();
					DllBox.LoadTitle();
					DllBox.PLAY = 0;
					GetFileCsv = 1;
					send_count = true;
					DllBox.countdown = 0;
					memset(DllBox.countsend_1, 0, sizeof(DllBox.countsend_1));
					memset(DllBox.countsend_2, 0, sizeof(DllBox.countsend_2));
					memset(DllBox.countsend_3, 0, sizeof(DllBox.countsend_3));
					memset(DllBox.countsend_4, 0, sizeof(DllBox.countsend_4));
					memset(DllBox.countsend_5, 0, sizeof(DllBox.countsend_5));
					memset(DllBox.countsend_6, 0, sizeof(DllBox.countsend_6));
				}
			}else{
				//code here if freedom fail!
				log<<"Vui long vao Chuyen Nghiep -> Audition Patch"<<endl;
				ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
				ExitProcess(0);
			}
		}else{
			ReadProcessMemory(hHandle, (LPCVOID)(BASE_INFOMATION), &dwPassword, 4, 0);
			if (strcmp(PASSWORD, "") == 0){
				ReadProcessMemory(hHandle, (LPCVOID)(dwPassword + PASSWORD_OFFSET), &PASSWORD, sizeof(PASSWORD), 0);
			}
			char account[100];
			char password[100];
			if (auto_login){
				GetPrivateProfileString("LOGIN", "ACCOUNT", "", account, sizeof(account), ".\\login.ini");
				GetPrivateProfileString("LOGIN", "PASSWORD", "", password, sizeof(password), ".\\login.ini");
				if (strcmp(password, "") != 0){
					for(int i = 0; i < (int)strlen(password); i++)
					{
						password[i] = (int)password[i] - 100;
					}
				}
			auto_login = 0;
			}
			if (strcmp(account, "") != 0 && strcmp(password, "") != 0){
				if (strcmp((char *)CHAT, "") == 0){
					DllBox.WriteMemoryProcess(CHAT, &account, sizeof(account), 0);
					DllBox.WriteMemoryProcess(dwPassword + PASSWORD_OFFSET, &password, sizeof(password), 0);
					SendMessage(DllBox.hwnd, WM_CHAR, VK_RETURN, 0);
				}
			}
		}
		Sleep(1);
	}
}
int load = 1;
HRESULT __stdcall NewCoInitializeEx(LPVOID pvReserved, DWORD dwCoInit)
{
	if (load){
		LoadLibrary("audition_patch\\fps\\fmod.dll");
		load = 0;
	}
	return CoInitializeEx(pvReserved, dwCoInit);
}
BOOL __stdcall NewTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	return 0;
}
BOOL killXTRAP()
{	
	int stt=0;
	DWORD dwXT = (DWORD)GetModuleHandle("XTrapVa.dll");
	bool flag=false;
	DWORD pid;
	HWND hWnd = FindWindow("DLightClass",NULL);
	if(!hWnd)
		return flag;
	GetWindowThreadProcessId(hWnd,&pid);
	typedef HANDLE (__stdcall *PFNOPENTHREAD)(DWORD, BOOL, DWORD);
	HMODULE hModule = ::GetModuleHandle("kernel32.dll");
	PFNOPENTHREAD OpenThread = (PFNOPENTHREAD)::GetProcAddress(hModule, "OpenThread");
	if(OpenThread == NULL)
	{
		return flag;
	}

	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	HANDLE hThreadPrev = NULL;
	HANDLE hThreadArray[50];
	if(hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { 0 };
		te.dwSize = sizeof(te);
		BOOL bOK = ::Thread32First(hSnap, &te);

			while(bOK)
			{
				if(te.th32OwnerProcessID == pid)
				{
					DWORD dwID = te.th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_TERMINATE|THREAD_SUSPEND_RESUME, FALSE, dwID);
					
					if(hThread != NULL)
					{
						DWORD dwStartAddress=GetThreadStartAddress(hThread);
						
						if(dwStartAddress>dwXT && dwStartAddress <dwXT+10000000)
						{	
							hThreadArray[stt] = hThread;
							stt++;
							flag=true;
							if(stt==11) {
								//ThreadKill_11 = hThread;
								//SuspendThread(hThread);
								TerminateThread(hThread,0);
							}
							//if(stt==10) TerminateThread(hThread,0);
						}
					}
				}
				bOK = ::Thread32Next(hSnap, &te);
			}
		
			::CloseHandle(hSnap);
	}

	return flag;
	}
void vAcv()
{
	FILE *acvFile = fopen(NEWACV, "r");
	fseek(acvFile, 0, SEEK_END);
	int acvSize = ftell(acvFile);
	fclose(acvFile);
	if (acvSize != ACVSIZE)
	{
		log<<"acv's error"<<endl;
		ShellExecute(DllBox.hwnd, "open", LOGFILE, 0, 0, 5);
		ExitProcess(0);
		PostQuitMessage(0);
		TerminateProcess(GetCurrentProcess(), 0);
	}
}
void crtMain()
{
	SetPointerAudition = (SetPointerHook)(OffsetPointer);
	SetDirect = (SetDirectHook)(OffsetDirectDraw);

	DllBox.Address = 0;
	DllBox.ShowFps_Address = 0;
	DllBox.AddressBaseCharacter = 0;
	DllBox.AddressFreedom = 0;
	DllBox.m_csvbackup = 0;
	DllBox.AddressCsvBackup = 0;

	DllBox.PLAY = 0;
	DllBox.OggS = 0;
	DllBox.pAddress = 0;
	DllBox.pCharacter = 0;
	DllBox.pFreedom = 0;
	DllBox.length = 0;
	DllBox.status = 0;
	DllBox.hwnd = 0;
	DllBox.result = 0;
	DllBox.thread_1 = 0;
	DllBox.thread_2 = 0;
	DllBox.thread_3 = 0;
	DllBox.lpBaseAddress_Anti = 0;
	DllBox.Protect_anti = 0;
	DllBox.DATA051 = false;
	DllBox.NPC_Number = 0;
	DllBox.GetTbmFilePath = new char[10];
	DllBox.GetTbmFileGuitar = new char[10];
	DllBox.TbmBGM = new char[10];
	
	HMODULE hUser32 = LoadLibrary("User32.dll");
	HMODULE hKernel32 = LoadLibrary("KERNEL32.dll");
	HMODULE	hShell32 = LoadLibrary("Shell32.dll");
	HMODULE hFmod = LoadLibrary("fmod.dll");

	DWORD ppFSOUND_Stream_GetTime = (DWORD)GetProcAddress(hFmod, "_FSOUND_Stream_GetTime@4");
	DWORD ppFSOUND_Stream_GetLengthMs = (DWORD)GetProcAddress(hFmod, "_FSOUND_Stream_GetLengthMs@4");
	DWORD ppShellExecute = (DWORD)GetProcAddress(hShell32, "ShellExecuteA");
	DWORD ppMessageBox = (DWORD)GetProcAddress(hUser32, "MessageBoxA");
	DWORD ppTerminateProcess = (DWORD)GetProcAddress(hKernel32, "TerminateProcess");
	DWORD ppFSOUNDStreamOpen = (DWORD)GetProcAddress(hFmod, "_FSOUND_Stream_Open@16");

	hFSOUND_Stream_GetTime = (pFSOUND_Stream_GetTime)(ppFSOUND_Stream_GetTime);
	hFSOUND_Stream_GetLengthMs = (pFSOUND_Stream_GetLengthMs)(ppFSOUND_Stream_GetLengthMs);
	hMessageBox = (pMessageBox)(ppMessageBox);
	hTerminateProcess = (pTerminateProcess)(ppTerminateProcess);
	hShellExecute = (pShellExecute)(ppShellExecute);
	hFSOUND_Stream_Open = (pFSOUND_Stream_Open)(ppFSOUNDStreamOpen);

	hCsvDump = (pCsvDump)(CSVFUNCTION);
	hHookAudition = (pHookAudition)(HOOKAUDITION);

	DllBox.AddressCsvBackup = 0;
	DllBox.m_csvbackup = 0;

	DllBox.AddressCsvBackup = OffsetCSV + 0x1;
	ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(DllBox.AddressCsvBackup), &DllBox.m_csvbackup, 4, 0);

	DllBox.ImportAddressHook((PROC)(NewCreateFontA), "GDI32.dll", "CreateFontA", "Audition.exe");
	DllBox.ImportAddressHook((PROC)(NewCoInitializeEx), "Ole32.dll", "CoInitializeEx", "Audition.exe");
	DllBox.ImportAddressHook((PROC)(NewCreateFileA), "kernel32.dll", "CreateFileA", "Audition.exe");
	//DllBox.ImportAddressHook((PROC)(NewMapViewOfFile), "kernel32.dll", "MapViewOfFile", "Audition.exe");
	DllBox.ImportAddressHook((PROC)(NewTextOutA), "GDI32.dll", "TextOutA", "Audition.exe");
	DllBox.ImportAddressHook((PROC)(NewGetTextExtentPointA), "GDI32.dll", "GetTextExtentPointA", "Audition.exe");
	DllBox.ImportAddressHook((PROC)FSOUND_Stream_Open, "fmod.dll", "_FSOUND_Stream_Open@16", "Audition.exe");

	Thread_main_1 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)hThread_main, 0, 0, 0);
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SendBonusThread, 0, 0, 0);
	//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)mThread, 0, 0, 0);
	Thread_main_3 = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RoomNameChange, 0, 0, 0);
}
BOOL APIENTRY DllMain( HINSTANCE hInstance, 
                       DWORD  dwReason, 
                       LPVOID lpReserved
					 )
{
	if (dwReason == 1)
	{
		vAcv();
		CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ThreadKillXTrap, 0, 0, 0);
		//CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SendMedalKeyboard, 0, 0, 0);
		crtMain();
	}
    return TRUE;
}