//commit
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <psapi.h>
#include <iostream>
#include <fstream>

#include "function.h"
#include "header.h"

using namespace std;
#pragma comment(lib, "psapi")

void PrintModules(HWND hwnd)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
    hProcess = GetCurrentProcess();
    if (NULL == hProcess)
        return;
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            TCHAR szModName[MAX_PATH];
			char data[100];
            if ( GetModuleFileNameEx(hProcess, hMods[i], szModName,sizeof(szModName) / sizeof(TCHAR)))
            {
                sprintf(data, "%s", szModName);//hMods[i] );
				
            }
        }
    }
    CloseHandle( hProcess );
    return;
}