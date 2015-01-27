#include <iostream>
#include <fstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "urlmon.lib")


#pragma warning(disable:4244)
#pragma warning(disable:4102)
#pragma warning(disable:4996)
#pragma warning(disable:4800)


typedef DWORD(WINAPI* _NtTerminateThread)(HANDLE,DWORD);
_NtTerminateThread NtTerminateThread;

using namespace std;

typedef LONG   NTSTATUS;
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9


typedef NTSTATUS (WINAPI *pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);
pNtQIT NtQueryInformationThread;

typedef int (WINAPI *lpEPMod) (HANDLE, HMODULE*, DWORD, DWORD*);
lpEPMod EnumProcessModules=NULL;
typedef int (WINAPI *lpGetModFNameEx) (HANDLE, HMODULE, LPTSTR, DWORD);
lpGetModFNameEx GetModuleFileNameEx=NULL;

#define STATUS_SUCCESS					((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH		((NTSTATUS)0xC0000004L)
#define OBJ_CASE_INSENSITIVE			0x00000040L
#define PAGE_READONLY					0x02
#define PAGE_READWRITE					0x04
#define DEF_KERNEL_BASE					0x80400000L
#define	SystemModuleInformation			11
#define PROT_MEMBASE					0x80000000

typedef LONG	NTSTATUS;
typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

DWORD gWinVersion;

typedef struct _STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION;

NTSTATUS (WINAPI * _RtlAnsiStringToUnicodeString)
	(PUNICODE_STRING  DestinationString,
	 IN PANSI_STRING  SourceString,
	 IN BOOLEAN);

VOID (WINAPI *_RtlInitAnsiString)
	(IN OUT PANSI_STRING  DestinationString,
	 IN PCHAR  SourceString);

VOID (WINAPI * _RtlFreeUnicodeString)
	(IN PUNICODE_STRING  UnicodeString);

NTSTATUS (WINAPI *_NtOpenSection)
	(OUT PHANDLE  SectionHandle,
	 IN ACCESS_MASK  DesiredAccess,
	 IN POBJECT_ATTRIBUTES  ObjectAttributes);

NTSTATUS (WINAPI *_NtMapViewOfSection)
	(IN HANDLE  SectionHandle,
	 IN HANDLE  ProcessHandle,
	 IN OUT PVOID  *BaseAddress,
	 IN ULONG  ZeroBits,
	 IN ULONG  CommitSize,
	 IN OUT PLARGE_INTEGER  SectionOffset,	/* optional */
	 IN OUT PULONG  ViewSize,
	 IN SECTION_INHERIT  InheritDisposition,
	 IN ULONG  AllocationType,
	 IN ULONG  Protect);

NTSTATUS (WINAPI *_NtUnmapViewOfSection)
	(IN HANDLE ProcessHandle,
	 IN PVOID BaseAddress);

NTSTATUS (WINAPI * _NtQuerySystemInformation)(UINT, PVOID, ULONG, PULONG);

//*******************************************************************************************************
// PE File structure declarations
//
//*******************************************************************************************************

struct PE_Header 
{
	unsigned long signature;
	unsigned short machine;
	unsigned short numSections;
	unsigned long timeDateStamp;
	unsigned long pointerToSymbolTable;
	unsigned long numOfSymbols;
	unsigned short sizeOfOptionHeader;
	unsigned short characteristics;
};

struct PE_ExtHeader
{
	unsigned short magic;
	unsigned char majorLinkerVersion;
	unsigned char minorLinkerVersion;
	unsigned long sizeOfCode;
	unsigned long sizeOfInitializedData;
	unsigned long sizeOfUninitializedData;
	unsigned long addressOfEntryPoint;
	unsigned long baseOfCode;
	unsigned long baseOfData;
	unsigned long imageBase;
	unsigned long sectionAlignment;
	unsigned long fileAlignment;
	unsigned short majorOSVersion;
	unsigned short minorOSVersion;
	unsigned short majorImageVersion;
	unsigned short minorImageVersion;
	unsigned short majorSubsystemVersion;
	unsigned short minorSubsystemVersion;
	unsigned long reserved1;
	unsigned long sizeOfImage;
	unsigned long sizeOfHeaders;
	unsigned long checksum;
	unsigned short subsystem;
	unsigned short DLLCharacteristics;
	unsigned long sizeOfStackReserve;
	unsigned long sizeOfStackCommit;
	unsigned long sizeOfHeapReserve;
	unsigned long sizeOfHeapCommit;
	unsigned long loaderFlags;
	unsigned long numberOfRVAAndSizes;
	unsigned long exportTableAddress;
	unsigned long exportTableSize;
	unsigned long importTableAddress;
	unsigned long importTableSize;
	unsigned long resourceTableAddress;
	unsigned long resourceTableSize;
	unsigned long exceptionTableAddress;
	unsigned long exceptionTableSize;
	unsigned long certFilePointer;
	unsigned long certTableSize;
	unsigned long relocationTableAddress;
	unsigned long relocationTableSize;
	unsigned long debugDataAddress;
	unsigned long debugDataSize;
	unsigned long archDataAddress;
	unsigned long archDataSize;
	unsigned long globalPtrAddress;
	unsigned long globalPtrSize;
	unsigned long TLSTableAddress;
	unsigned long TLSTableSize;
	unsigned long loadConfigTableAddress;
	unsigned long loadConfigTableSize;
	unsigned long boundImportTableAddress;
	unsigned long boundImportTableSize;
	unsigned long importAddressTableAddress;
	unsigned long importAddressTableSize;
	unsigned long delayImportDescAddress;
	unsigned long delayImportDescSize;
	unsigned long COMHeaderAddress;
	unsigned long COMHeaderSize;
	unsigned long reserved2;
	unsigned long reserved3;
};


struct SectionHeader
{
	unsigned char sectionName[8];
	unsigned long virtualSize;
	unsigned long virtualAddress;
	unsigned long sizeOfRawData;
	unsigned long pointerToRawData;
	unsigned long pointerToRelocations;
	unsigned long pointerToLineNumbers;
	unsigned short numberOfRelocations;
	unsigned short numberOfLineNumbers;
	unsigned long characteristics;
};

struct MZHeader
{
	unsigned short signature;
	unsigned short partPag;
	unsigned short pageCnt;
	unsigned short reloCnt;
	unsigned short hdrSize;
	unsigned short minMem;
	unsigned short maxMem;
	unsigned short reloSS;
	unsigned short exeSP;
	unsigned short chksum;
	unsigned short exeIP;
	unsigned short reloCS;
	unsigned short tablOff;
	unsigned short overlay;
	unsigned char reserved[32];
	unsigned long offsetToPE;
};


struct ImportDirEntry
{
	DWORD importLookupTable;
	DWORD timeDateStamp;
	DWORD fowarderChain;
	DWORD nameRVA;
	DWORD importAddressTable;
};


DWORD myStrlenA(char *ptr)
{
	DWORD len = 0;
	while(*ptr)
	{
		len++;
		ptr++;
	}

	return len;
}







int URLGetPage(char *link, char *buffer, int maxsize)
{
	HINTERNET hSession;  
	HINTERNET hURL;
	DWORD dwBYTEsRead;
	int ok;

	ok=0;
	buffer[0]=0;
	hSession = InternetOpen("Microsoft Internet Explorer",INTERNET_OPEN_TYPE_PRECONFIG,NULL, NULL, 0);
	if (hSession)
	{
		hURL = InternetOpenUrl(hSession,link,NULL, 0, 0, 0);
		if (hURL)
		{
			InternetReadFile(hURL,(LPSTR)buffer,(DWORD)maxsize,&dwBYTEsRead);
			InternetCloseHandle(hURL);
			buffer[dwBYTEsRead]=0;
			ok=(int)dwBYTEsRead;
		}
		InternetCloseHandle(hSession);
	}
	return ok;
}

BOOL myStrcmpA(char *str1, char *str2)
{
	while(*str1 && *str2)
	{
		if(*str1 == *str2)
		{
			str1++;
			str2++;
		}
		else
		{
			return FALSE;
		}
	}

	if(*str1 && !*str2)
	{
		return FALSE;
	}
	else if(*str2 && !*str1)
	{
		return FALSE;
	}

	return TRUE;	
}
//******************************************************************************


DWORD WINAPI GetThreadStartAddress(HANDLE hThread)
{
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	DWORD dwStartAddress;
	NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	if(NtQueryInformationThread == NULL) return 0;
	HANDLE hCurrentProcess = GetCurrentProcess();
	if(!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){
		SetLastError(ERROR_ACCESS_DENIED);
		return 0;
	}
	ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);
	CloseHandle(hDupHandle);
	if(ntStatus != STATUS_SUCCESS)
		return 0;
	return dwStartAddress;
}


HMODULE GetAddressModules( DWORD processID,char ModName[MAX_PATH])
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;
		
    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID );
    if (NULL == hProcess)
        return 0;
	
    if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
        {
            char szModName[MAX_PATH];			
            if ( GetModuleFileNameEx( hProcess, hMods[i], szModName,sizeof(szModName)))
            {
				
				if(strstr(szModName,ModName))
				{
//					//printf( "\t%s (0x%08X)\n", szModName, hMods[i] );
					return hMods[i];
				}
            }
        }
    }
	
    CloseHandle( hProcess );
	return 0;
}
//*************************************************************
DWORD GetModuleBase(LPSTR lpModuleName, DWORD dwProcessId)
{
   MODULEENTRY32 lpModuleEntry = {0};
   HANDLE hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwProcessId );
 
   if(!hSnapShot)
      return NULL;
   lpModuleEntry.dwSize = sizeof(lpModuleEntry);
   BOOL bModule = Module32First( hSnapShot, &lpModuleEntry );
   while(bModule)
   {
      if(!strcmp( lpModuleEntry.szModule, lpModuleName ) )
      {
         CloseHandle( hSnapShot );
         return (DWORD)lpModuleEntry.modBaseAddr;
      }
      bModule = Module32Next( hSnapShot, &lpModuleEntry );
   }
   CloseHandle( hSnapShot );
   return NULL;
}
//***************************************** FindProcess **************************************************
bool SoSanhChuoi (char s1[],char s2[])
{
	int x=strlen (s1);
	int y=strlen (s2);
	if (x!=y) return 0;
	for (int i=0;i<x;i++)
	if (s1[i]!=s2[i]) 
	{
		int q=abs (s1[i]-s2[i]);
		if (q!=32)	return 0;
		
	}
	return 1;
}

DWORD FindProcess (LPSTR lpExePath)
{
	PROCESSENTRY32 Pe32;
	DWORD dwProcessId=0;
	HANDLE   hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);    
    Pe32.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnapShot, &Pe32);
    do
    {     
		if (SoSanhChuoi (Pe32.szExeFile, lpExePath))
		{
			dwProcessId = Pe32.th32ProcessID;
			CloseHandle (hSnapShot);
			return dwProcessId; 
		}              
     }while (Process32Next(hSnapShot, &Pe32));      
     CloseHandle (hSnapShot);
return 0;
}

bool  FindFile (char * szPath    )
{
    WIN32_FIND_DATA ffd;
    HANDLE          SearchHandle;

    if ( (SearchHandle = FindFirstFile (szPath, &ffd )) == INVALID_HANDLE_VALUE ) return 0;
    else 
	{
        FindClose( SearchHandle );
        return 1;
   }
}
	
	

bool  FileExit(char * szPath    )
{
    WIN32_FIND_DATA ffd;
    HANDLE          SearchHandle;

    if ( (SearchHandle = FindFirstFile (szPath, &ffd )) == INVALID_HANDLE_VALUE ) return 0;
    else 
	{
        FindClose( SearchHandle );
        return 1;
   }
}

//*******************************************************************************************************
// Fills the various structures with info of a PE image.  The PE image is located at modulePos.
//
//*******************************************************************************************************

bool readPEInfo(char *modulePos, MZHeader *outMZ, PE_Header *outPE, PE_ExtHeader *outpeXH,
				SectionHeader **outSecHdr)
{
	// read MZ Header
	MZHeader *mzH;
	mzH = (MZHeader *)modulePos;

	if(mzH->signature != 0x5a4d)		// MZ
	{
		//printf("File does not have MZ header\n");
		return false;
	}

	// read PE Header
	PE_Header *peH;
	peH = (PE_Header *)(modulePos + mzH->offsetToPE);

	if(peH->sizeOfOptionHeader != sizeof(PE_ExtHeader))
	{
		//printf("Unexpected option header size.\n");
		
		return false;
	}

	// read PE Ext Header
	PE_ExtHeader *peXH;
	peXH = (PE_ExtHeader *)((char *)peH + sizeof(PE_Header));

	// read the sections
	SectionHeader *secHdr = (SectionHeader *)((char *)peXH + sizeof(PE_ExtHeader));

	*outMZ = *mzH;
	*outPE = *peH;
	*outpeXH = *peXH;
	*outSecHdr = secHdr;

	return true;
}


//*******************************************************************************************************
// Returns the total size required to load a PE image into memory
//
//*******************************************************************************************************

int calcTotalImageSize(MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
				       SectionHeader *inSecHdr)
{
	int result = 0;
	int alignment = inpeXH->sectionAlignment;

	if(inpeXH->sizeOfHeaders % alignment == 0)
		result += inpeXH->sizeOfHeaders;
	else
	{
		int val = inpeXH->sizeOfHeaders / alignment;
		val++;
		result += (val * alignment);
	}
	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].virtualSize)
		{
			if(inSecHdr[i].virtualSize % alignment == 0)
				result += inSecHdr[i].virtualSize;
			else
			{
				int val = inSecHdr[i].virtualSize / alignment;
				val++;
				result += (val * alignment);
			}
		}
	}

	return result;
}


//*******************************************************************************************************
// Returns the aligned size of a section
//
//*******************************************************************************************************

unsigned long getAlignedSize(unsigned long curSize, unsigned long alignment)
{	
	if(curSize % alignment == 0)
		return curSize;
	else
	{
		int val = curSize / alignment;
		val++;
		return (val * alignment);
	}
}

//*******************************************************************************************************
// Copy a PE image from exePtr to ptrLoc with proper memory alignment of all sections
//
//*******************************************************************************************************

bool loadPE(char *exePtr, MZHeader *inMZ, PE_Header *inPE, PE_ExtHeader *inpeXH,
			SectionHeader *inSecHdr, LPVOID ptrLoc)
{
	char *outPtr = (char *)ptrLoc;
	
	memcpy(outPtr, exePtr, inpeXH->sizeOfHeaders);
	outPtr += getAlignedSize(inpeXH->sizeOfHeaders, inpeXH->sectionAlignment);

	for(int i = 0; i < inPE->numSections; i++)
	{
		if(inSecHdr[i].sizeOfRawData > 0)
		{
			unsigned long toRead = inSecHdr[i].sizeOfRawData;
			if(toRead > inSecHdr[i].virtualSize)
				toRead = inSecHdr[i].virtualSize;

			memcpy(outPtr, exePtr + inSecHdr[i].pointerToRawData, toRead);

			outPtr += getAlignedSize(inSecHdr[i].virtualSize, inpeXH->sectionAlignment);
		}
	}

	return true;
}


//*******************************************************************************************************
// Loads the DLL into memory and align it
//
//*******************************************************************************************************

LPVOID loadDLL(char *dllName)
{
	char moduleFilename[MAX_PATH + 1];
	LPVOID ptrLoc = NULL;
	MZHeader mzH2;
	PE_Header peH2;
	PE_ExtHeader peXH2;
	SectionHeader *secHdr2;

	GetSystemDirectory(moduleFilename, MAX_PATH);
	if((myStrlenA(moduleFilename) + myStrlenA(dllName)) >= MAX_PATH)
		return NULL;

	strcat(moduleFilename, dllName);

	// load this EXE into memory because we need its original Import Hint Table

	HANDLE fp;
	fp = CreateFile(moduleFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	
	if(fp != INVALID_HANDLE_VALUE)
	{
		BY_HANDLE_FILE_INFORMATION fileInfo;
		GetFileInformationByHandle(fp, &fileInfo);

		DWORD fileSize = fileInfo.nFileSizeLow;
		////printf("Size = %d\n", fileSize);
		if(fileSize)
		{
			LPVOID exePtr = HeapAlloc(GetProcessHeap(), 0, fileSize);
			if(exePtr)
			{
				DWORD read;

				if(ReadFile(fp, exePtr, fileSize, &read, NULL) && read == fileSize)
				{					
					if(readPEInfo((char *)exePtr, &mzH2, &peH2, &peXH2, &secHdr2))
					{
						int imageSize = calcTotalImageSize(&mzH2, &peH2, &peXH2, secHdr2);						

						//ptrLoc = VirtualAlloc(NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						ptrLoc = HeapAlloc(GetProcessHeap(), 0, imageSize);
						if(ptrLoc)
						{							
							loadPE((char *)exePtr, &mzH2, &peH2, &peXH2, secHdr2, ptrLoc);
						}
					}

				}
				HeapFree(GetProcessHeap(), 0, exePtr);
			}
		}
		CloseHandle(fp);
	}

	return ptrLoc;
}


DWORD procAPIExportAddr(DWORD hModule, char *apiName)
{	
	if(!hModule || !apiName)
		return 0;

	char *ptr = (char *)hModule;
	ptr += 0x3c;		// offset 0x3c contains offset to PE header
	
	ptr = (char *)(*(DWORD *)ptr) + hModule + 0x78;		// offset 78h into PE header contains addr of export table

	ptr = (char *)(*(DWORD *)ptr) + hModule;			// ptr now points to export directory table

	// offset 24 into the export directory table == number of entries in the Export Name Pointer Table
	// table
	DWORD numEntries = *(DWORD *)(ptr + 24);
	////printf("NumEntries = %d\n", numEntries);

	DWORD *ExportNamePointerTable = (DWORD *)(*(DWORD *)(ptr + 32) + hModule);  // offset 32 into export directory contains offset to Export Name Pointer Table	
	
	DWORD ordinalBase = *((DWORD *)(ptr + 16));
	////printf("OrdinalBase is %d\n", ordinalBase);


	WORD *ExportOrdinalTable = (WORD *)((*(DWORD *)(ptr + 36)) + hModule);	// offset 36 into export directory contains offset to Ordinal Table
	DWORD *ExportAddrTable = (DWORD *)((*(DWORD *)(ptr + 28)) + hModule); // offset 28 into export directory contains offset to Export Addr Table

	for(DWORD i = 0; i < numEntries; i++)
	{		
		char *exportName = (char *)(ExportNamePointerTable[i] + hModule);

		if(myStrcmpA(exportName, apiName) == TRUE)
		{			
			WORD ordinal = ExportOrdinalTable[i];
			////printf("%s (i = %d) Ordinal = %d at %X\n", exportName, i, ordinal, ExportAddrTable[ordinal]);

			return (DWORD)(ExportAddrTable[ordinal]);
		}		
	}

	return 0;
}

//*******************************************************************************************************
// -- END PE File support functions --
//
//*******************************************************************************************************


//*********************************************************************************************
// Builds a table of native API names using the export table of ntdll.dll
//
//*********************************************************************************************

BOOL buildNativeAPITable(DWORD hModule, char *nativeAPINames[], DWORD numNames)
{
	if(!hModule)
		return FALSE;

	char *ptr = (char *)hModule;
	ptr += 0x3c;		// offset 0x3c contains offset to PE header
	
	ptr = (char *)(*(DWORD *)ptr) + hModule + 0x78;		// offset 78h into PE header contains addr of export table

	ptr = (char *)(*(DWORD *)ptr) + hModule;			// ptr now points to export directory table

	
	// offset 24 into the export directory table == number of entries in the Name Pointer Table
	// table
	DWORD numEntries = *(DWORD *)(ptr + 24);	
	
	DWORD *ExportNamePointerTable = (DWORD *)(*(DWORD *)(ptr + 32) + hModule);  // offset 32 into export directory contains offset to Export Name Pointer Table	

	DWORD ordinalBase = *((DWORD *)(ptr + 16));

	WORD *ExportOrdinalTable = (WORD *)((*(DWORD *)(ptr + 36)) + hModule);	// offset 36 into export directory contains offset to Ordinal Table
	DWORD *ExportAddrTable = (DWORD *)((*(DWORD *)(ptr + 28)) + hModule); // offset 28 into export directory contains offset to Export Addr Table


	for(DWORD i = 0; i < numEntries; i++)
	{		
		// i now contains the index of the API in the Ordinal Table
		// ptr points to Export directory table

		WORD ordinalValue = ExportOrdinalTable[i];		
		DWORD apiAddr = (DWORD)ExportAddrTable[ordinalValue] + hModule;
		char *exportName = (char *)(ExportNamePointerTable[i] + hModule);
		
		// Win2K
		if(gWinVersion == 0 &&
		   *((unsigned char *)apiAddr) == 0xB8 && 
		   *((unsigned char *)apiAddr + 9) == 0xCD && 
		   *((unsigned char *)apiAddr + 10) == 0x2E)
		{
			DWORD serviceNum = *(DWORD *)((char *)apiAddr + 1);
			if(serviceNum < numNames)
			{
				nativeAPINames[serviceNum] = exportName;
			}
			////printf("%X - %s\n", serviceNum, exportName);
		}

		// WinXP
		else if(gWinVersion == 1 &&
				*((unsigned char *)apiAddr) == 0xB8 && 
				*((unsigned char *)apiAddr + 5) == 0xBA && 
				*((unsigned char *)apiAddr + 6) == 0x00 &&
				*((unsigned char *)apiAddr + 7) == 0x03 &&
				*((unsigned char *)apiAddr + 8) == 0xFE &&
				*((unsigned char *)apiAddr + 9) == 0x7F)
		{
			DWORD serviceNum = *(DWORD *)((char *)apiAddr + 1);
			if(serviceNum < numNames)
			{
				nativeAPINames[serviceNum] = exportName;
			}
			////printf("%X - %s\n", serviceNum, exportName);
		}
	}

	return TRUE;
}


//*******************************************************************************************************
// Gets address of native API's that we'll be using
//
//*******************************************************************************************************

BOOL getNativeAPIs(void)
{
	HMODULE hntdll;

	hntdll = GetModuleHandle("ntdll.dll");
			
	*(FARPROC *)&_RtlAnsiStringToUnicodeString = 
			GetProcAddress(hntdll, "RtlAnsiStringToUnicodeString");

	*(FARPROC *)&_RtlInitAnsiString = 
			GetProcAddress(hntdll, "RtlInitAnsiString");

	*(FARPROC *)&_RtlFreeUnicodeString = 
			GetProcAddress(hntdll, "RtlFreeUnicodeString");

	*(FARPROC *)&_NtOpenSection =
			GetProcAddress(hntdll, "NtOpenSection");

	*(FARPROC *)&_NtMapViewOfSection =
			GetProcAddress(hntdll, "NtMapViewOfSection");

	*(FARPROC *)&_NtUnmapViewOfSection =
			GetProcAddress(hntdll, "NtUnmapViewOfSection");

	*(FARPROC *)&_NtQuerySystemInformation =
		GetProcAddress(hntdll, "ZwQuerySystemInformation");

	if(_RtlAnsiStringToUnicodeString && _RtlInitAnsiString && _RtlFreeUnicodeString &&
		_NtOpenSection && _NtMapViewOfSection && _NtUnmapViewOfSection && _NtQuerySystemInformation)
	{
		return TRUE;
	}
	return FALSE;
}


//*******************************************************************************************************
// Obtain a handle to \device\physicalmemory
//
//*******************************************************************************************************

HANDLE openPhyMem()
{
	HANDLE hPhyMem;
	OBJECT_ATTRIBUTES oAttr;

	ANSI_STRING aStr;
		
	_RtlInitAnsiString(&aStr, "\\device\\physicalmemory");
						
	UNICODE_STRING uStr;

	if(_RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
	{		
		return INVALID_HANDLE_VALUE;	
	}

    oAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    oAttr.RootDirectory = NULL;
    oAttr.Attributes = OBJ_CASE_INSENSITIVE;
    oAttr.ObjectName = &uStr;
    oAttr.SecurityDescriptor = NULL;
    oAttr.SecurityQualityOfService = NULL;

	if(_NtOpenSection(&hPhyMem, SECTION_MAP_READ | SECTION_MAP_WRITE, &oAttr ) != STATUS_SUCCESS)
	{		
		return INVALID_HANDLE_VALUE;
	}

	return hPhyMem;
}
//*******************************************************************************************************
// Map in a section of physical memory into this process's virtual address space.
//
//*******************************************************************************************************

BOOL mapPhyMem(HANDLE hPhyMem, DWORD *phyAddr, DWORD *length, PVOID *virtualAddr)
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	viewBase;

	*virtualAddr = 0;
	viewBase.QuadPart = (ULONGLONG) (*phyAddr);

	ntStatus = _NtMapViewOfSection(hPhyMem, (HANDLE)-1, virtualAddr, 0,
								*length, &viewBase, length,
                                ViewShare, 0, PAGE_READWRITE );

	if(ntStatus != STATUS_SUCCESS)
	{
		//printf("Failed to map physical memory view of length %X at %X!", *length, *phyAddr);
		return FALSE;					
	}

	*phyAddr = viewBase.LowPart;
	return TRUE;
}


//*******************************************************************************************************
// Unmap section of physical memory
//
//*******************************************************************************************************

void unmapPhyMem(DWORD virtualAddr)
{
	NTSTATUS status;

	status = _NtUnmapViewOfSection((HANDLE)-1, (PVOID)virtualAddr);
	if(status != STATUS_SUCCESS)
	{
		//printf("Unmapping view failed!\n");
	}
}


//*******************************************************************************************************
// Assign SECTION_MAP_WRITE assess of \device\physicalmemory to current user.
//
//*******************************************************************************************************

BOOL assignACL(void)
{
	HANDLE hPhyMem;
	OBJECT_ATTRIBUTES oAttr;
	BOOL result = FALSE;

	ANSI_STRING aStr;
		
	_RtlInitAnsiString(&aStr, "\\device\\physicalmemory");
						
	UNICODE_STRING uStr;

	if(_RtlAnsiStringToUnicodeString(&uStr, &aStr, TRUE) != STATUS_SUCCESS)
	{		
		return FALSE;
	}

    oAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    oAttr.RootDirectory = NULL;
    oAttr.Attributes = OBJ_CASE_INSENSITIVE;
    oAttr.ObjectName = &uStr;
    oAttr.SecurityDescriptor = NULL;
    oAttr.SecurityQualityOfService = NULL;

	if(_NtOpenSection(&hPhyMem, READ_CONTROL | WRITE_DAC, &oAttr ) != STATUS_SUCCESS)
	{		
		return FALSE;
	}
	else
	{
		PACL dacl;
		PSECURITY_DESCRIPTOR sd;
		
		if(GetSecurityInfo(hPhyMem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
						&dacl, NULL, &sd) == ERROR_SUCCESS)
		{
			EXPLICIT_ACCESS ea;
			char userName[MAX_PATH];
			DWORD userNameSize = MAX_PATH-1;

			GetUserName(userName, &userNameSize);
			ea.grfAccessPermissions = SECTION_MAP_WRITE;
			ea.grfAccessMode = GRANT_ACCESS;
			ea.grfInheritance = NO_INHERITANCE;
			ea.Trustee.pMultipleTrustee = NULL;
			ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
			ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
			ea.Trustee.ptstrName = userName;

			PACL newDacl;
			if(SetEntriesInAcl(1, &ea, dacl, &newDacl) == ERROR_SUCCESS)
			{
				if(SetSecurityInfo(hPhyMem, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL,
								newDacl, NULL) == ERROR_SUCCESS)
				{		
					result = TRUE;
				}

				LocalFree(newDacl);
			}
		}
	}

	return result;	
}


//*******************************************************************************************************
// Gets the kernel base address
//
//*******************************************************************************************************

DWORD getKernelBase(void)
{
	HANDLE hHeap = GetProcessHeap();
	
	NTSTATUS Status;
    ULONG cbBuffer = 0x8000;
    PVOID pBuffer = NULL;
	DWORD retVal = DEF_KERNEL_BASE;

    do
    {
		pBuffer = HeapAlloc(hHeap, 0, cbBuffer);
		if (pBuffer == NULL)
			return DEF_KERNEL_BASE;

		Status = _NtQuerySystemInformation(SystemModuleInformation,
					pBuffer, cbBuffer, NULL);

		if(Status == STATUS_INFO_LENGTH_MISMATCH)
		{
			HeapFree(hHeap, 0, pBuffer);
			cbBuffer *= 2;
		}
		else if(Status != STATUS_SUCCESS)
		{
			HeapFree(hHeap, 0, pBuffer);
			return DEF_KERNEL_BASE;
		}
    }
    while (Status == STATUS_INFO_LENGTH_MISMATCH);

	DWORD numEntries = *((DWORD *)pBuffer);
	SYSTEM_MODULE_INFORMATION *smi = (SYSTEM_MODULE_INFORMATION *)((char *)pBuffer + sizeof(DWORD));

	for(DWORD i = 0; i < numEntries; i++)
	{
		if(strcmpi(smi->ImageName, "ntkrnlpa.exe"))
		{
			////printf("%.8X - %s\n", smi->Base, smi->ImageName);
			retVal = (DWORD)(smi->Base);
			break;
		}
		smi++;
	}

	HeapFree(hHeap, 0, pBuffer);

	return retVal;
}


struct FixupBlock
{
	unsigned long pageRVA;
	unsigned long blockSize;
};



BOOL checkKiServiceTableAddr(PVOID exeAddr, DWORD chkAddr, PE_ExtHeader *peXH2)
{
	if(peXH2->relocationTableAddress && peXH2->relocationTableSize)
	{
		FixupBlock *fixBlk = (FixupBlock *)((char *)exeAddr + peXH2->relocationTableAddress);		

		while(fixBlk->blockSize)
		{
			int numEntries = (fixBlk->blockSize - sizeof(FixupBlock)) >> 1;
	
			unsigned short *offsetPtr = (unsigned short *)(fixBlk + 1);

			for(int i = 0; i < numEntries; i++)
			{				
				int relocType = (*offsetPtr & 0xF000) >> 12;
				
				if(relocType == 3)
				{
					DWORD *codeLoc = (DWORD *)((char *)exeAddr + fixBlk->pageRVA + (*offsetPtr & 0x0FFF));
					
					if(fixBlk->pageRVA + (*offsetPtr & 0x0FFF) + peXH2->imageBase == chkAddr)
					{
						return TRUE;
					}
				}
				offsetPtr++;
			}
			fixBlk = (FixupBlock *)offsetPtr;
		}
	}
	return FALSE;
}


// Thanks to 90210 for this excellent way of getting the KiServiceTable address from the disk image of
// ntkrnlpa.exe
// http://www.rootkit.com/newsread.php?newsid=176

DWORD getKiServiceTableAddr(PVOID exeAddr, DWORD sdtAddr, PE_ExtHeader *peXH2)
{
	if(peXH2->relocationTableAddress && peXH2->relocationTableSize)
	{
		FixupBlock *fixBlk = (FixupBlock *)((char *)exeAddr + peXH2->relocationTableAddress);		

		while(fixBlk->blockSize)
		{
			////printf("Addr = %X\n", fixBlk->pageRVA);
			////printf("Size = %X\n", fixBlk->blockSize);

			int numEntries = (fixBlk->blockSize - sizeof(FixupBlock)) >> 1;
			////printf("Num Entries = %d\n", numEntries);

			unsigned short *offsetPtr = (unsigned short *)(fixBlk + 1);

			for(int i = 0; i < numEntries; i++)
			{				
				int relocType = (*offsetPtr & 0xF000) >> 12;
				
				////printf("Val = %X\n", *offsetPtr);
				////printf("Type = %X\n", relocType);

				if(relocType == 3)
				{
					DWORD *codeLoc = (DWORD *)((char *)exeAddr + fixBlk->pageRVA + (*offsetPtr & 0x0FFF));					

					if(*codeLoc == sdtAddr + peXH2->imageBase &&
						*(WORD *)((DWORD)codeLoc - 2) == 0x05c7)
					{
						DWORD kiServiceTableAddr = *(DWORD *)((DWORD)codeLoc + 4);
						
						// checks for presence of found address in the relocation table
						if(checkKiServiceTableAddr(exeAddr, kiServiceTableAddr, peXH2))
						{
							return kiServiceTableAddr - peXH2->imageBase;
						}
					}						
				}

				offsetPtr++;
			}

			fixBlk = (FixupBlock *)offsetPtr;
		}
	}
	return 0;
}

//*******************************************************************************************************
// Program entry point
// No commandline arguments required.
//
//*******************************************************************************************************


//********* SuspendProcess ******************************************************************************
BOOL WINAPI SuspendProcess(DWORD dwProcessID, BOOL bSuspend)
{
// OpenThread
	typedef HANDLE (__stdcall *PFNOPENTHREAD)(DWORD, BOOL, DWORD);
	HMODULE hModule = ::GetModuleHandle("kernel32.dll");
	PFNOPENTHREAD OpenThread = (PFNOPENTHREAD)::GetProcAddress(hModule, "OpenThread");

	if(OpenThread == NULL)
	{
		return FALSE;
	}

	HANDLE hSnap;
	hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);

	if(hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { 0 };
		te.dwSize = sizeof(te);
		BOOL bOK = ::Thread32First(hSnap, &te);
			while(bOK)
			{
				if(te.th32OwnerProcessID == dwProcessID)
				{
					DWORD dwID = te.th32ThreadID;
					HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwID);
						if(hThread != NULL)
						{
							if(bSuspend)
							{
								::SuspendThread(hThread);
							}
							else
							{
								::ResumeThread(hThread);
								::CloseHandle(hThread);
							}
						}
				}
				bOK = ::Thread32Next(hSnap, &te);
			}
			::CloseHandle(hSnap);
	}
	return TRUE;
}
DWORD WINAPI KillProcess(DWORD dwProcessID, int i)
{
	int stt=0;
	int stt2 = 0;
	DWORD flag=0;

	typedef HANDLE (__stdcall *PFNOPENTHREAD)(DWORD, BOOL, DWORD);
	HMODULE hModule = ::GetModuleHandle("kernel32.dll");
	PFNOPENTHREAD OpenThread = (PFNOPENTHREAD)::GetProcAddress(hModule, "OpenThread");

	if(OpenThread == NULL) return flag;

	HANDLE hSnap;
	hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);

	if(hSnap != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { 0 };
		te.dwSize = sizeof(te);
		BOOL bOK = ::Thread32First(hSnap, &te);
			while(bOK)
			{
				if(te.th32OwnerProcessID == dwProcessID)
				{
					DWORD dwID = te.th32ThreadID;
					HANDLE hThread = OpenThread(STANDARD_RIGHTS_REQUIRED||THREAD_SUSPEND_RESUME, FALSE, dwID);
						if(hThread != NULL){	
							if(i==1) // Kill Thread cua Xtrap
							{
								//0x407a80
								//0x4089e0
								//0x40c290
								//0x407340
								//0x759000
								
								if(GetThreadStartAddress(hThread)> 0x400000){
									TerminateThread(hThread,0);
								}
								flag=1;
								return flag;
							}
							if(i==2){
								if(GetThreadStartAddress(hThread)>1070000000 && GetThreadStartAddress(hThread) <1070000000+100000000){
									stt++;
									//3, 7, 8, 10, 11
									if(stt==11)
									{
										//Sleep(5000);
										//TerminateThread(hThread,0);
										SuspendThread(hThread);
										flag=2;
									}
								}
							}

						}
				}
				bOK = ::Thread32Next(hSnap, &te); 
			}
			::CloseHandle(hSnap);
	}
	return flag;
}


BOOL MatchAddressToModule(DWORD dwProcId, char * lpstrModule, DWORD dwThreadStartAddr, PDWORD pModuleStartAddr) // by Echo
{
    BOOL bRet = FALSE;
	HANDLE hSnapshot;
	MODULEENTRY32 moduleEntry32;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPALL, dwProcId);

	moduleEntry32.dwSize = sizeof(MODULEENTRY32);
	moduleEntry32.th32ModuleID = 1;

	if(Module32First(hSnapshot, &moduleEntry32)){
	    if(dwThreadStartAddr >= (DWORD)moduleEntry32.modBaseAddr && dwThreadStartAddr <= ((DWORD)moduleEntry32.modBaseAddr + moduleEntry32.modBaseSize)){
            _tcscpy(lpstrModule, moduleEntry32.szExePath);
	    }else{
            while(Module32Next(hSnapshot, &moduleEntry32)){
                if(dwThreadStartAddr >= (DWORD)moduleEntry32.modBaseAddr && dwThreadStartAddr <= ((DWORD)moduleEntry32.modBaseAddr + moduleEntry32.modBaseSize)){
                    _tcscpy(lpstrModule, moduleEntry32.szExePath);
                    break;
                }
            }
	    }
    }

    if(pModuleStartAddr) *pModuleStartAddr = (DWORD)moduleEntry32.modBaseAddr;
	CloseHandle(hSnapshot);

	return bRet;
}

/////////////////////////////////////////////////////////////////////////////////////////////
int KILL_PROC_BY_NAME(const char *szToTerminate)

{
    BOOL bResult,bResultm;
    DWORD aiPID[1000],iCb=1000,iNumProc,iV2000=0;
    DWORD iCbneeded,i,iFound=0;
    char szName[MAX_PATH],szToTermUpper[MAX_PATH];
    HANDLE hProc,hSnapShot,hSnapShotm;
    OSVERSIONINFO osvi;
    HINSTANCE hInstLib;
    int iLen,iLenP,indx;
    HMODULE hMod;
    PROCESSENTRY32 procentry;      
    MODULEENTRY32 modentry;

    // Transfer Process name into "szToTermUpper" and
    // convert it to upper case
    iLenP=strlen(szToTerminate);
    if(iLenP<1 || iLenP>MAX_PATH) return 632;
    for(indx=0;indx<iLenP;indx++)
        szToTermUpper[indx]=toupper(szToTerminate[indx]);
    szToTermUpper[iLenP]=0;

     // PSAPI Function Pointers.
     BOOL (WINAPI *lpfEnumProcesses)( DWORD *, DWORD cb, DWORD * );
     BOOL (WINAPI *lpfEnumProcessModules)( HANDLE, HMODULE *,
        DWORD, LPDWORD );
     DWORD (WINAPI *lpfGetModuleBaseName)( HANDLE, HMODULE,
        LPTSTR, DWORD );

      // ToolHelp Function Pointers.
      HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD,DWORD) ;
      BOOL (WINAPI *lpfProcess32First)(HANDLE,LPPROCESSENTRY32) ;
      BOOL (WINAPI *lpfProcess32Next)(HANDLE,LPPROCESSENTRY32) ;
      BOOL (WINAPI *lpfModule32First)(HANDLE,LPMODULEENTRY32) ;
      BOOL (WINAPI *lpfModule32Next)(HANDLE,LPMODULEENTRY32) ;

    // First check what version of Windows we're in
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    bResult=GetVersionEx(&osvi);
    if(!bResult)     // Unable to identify system version
        return 606;

    // At Present we only support Win/NT/2000/XP or Win/9x/ME
    if((osvi.dwPlatformId != VER_PLATFORM_WIN32_NT) &&
        (osvi.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS))
        return 607;

    if(osvi.dwPlatformId==VER_PLATFORM_WIN32_NT)
    {
        // Win/NT or 2000 or XP

         // Load library and get the procedures explicitly. We do
         // this so that we don't have to worry about modules using
         // this code failing to load under Windows 9x, because
         // it can't resolve references to the PSAPI.DLL.
         hInstLib = LoadLibraryA("PSAPI.DLL");
         if(hInstLib == NULL)
            return 605;

         // Get procedure addresses.
         lpfEnumProcesses = (BOOL(WINAPI *)(DWORD *,DWORD,DWORD*))
            GetProcAddress( hInstLib, "EnumProcesses" ) ;
         lpfEnumProcessModules = (BOOL(WINAPI *)(HANDLE, HMODULE *,
            DWORD, LPDWORD)) GetProcAddress( hInstLib,
            "EnumProcessModules" ) ;
         lpfGetModuleBaseName =(DWORD (WINAPI *)(HANDLE, HMODULE,
            LPTSTR, DWORD )) GetProcAddress( hInstLib,
            "GetModuleBaseNameA" ) ;

         if(lpfEnumProcesses == NULL ||
            lpfEnumProcessModules == NULL ||
            lpfGetModuleBaseName == NULL)
            {
               FreeLibrary(hInstLib);
               return 700;
            }
         
        bResult=lpfEnumProcesses(aiPID,iCb,&iCbneeded);
        if(!bResult)
        {
            // Unable to get process list, EnumProcesses failed
            FreeLibrary(hInstLib);
            return 701;
        }

        // How many processes are there?
        iNumProc=iCbneeded/sizeof(DWORD);

        // Get and match the name of each process
        for(i=0;i<iNumProc;i++)
        {
            // Get the (module) name for this process

            strcpy(szName,"Unknown");
            // First, get a handle to the process
            hProc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,
                aiPID[i]);
            // Now, get the process name
            if(hProc)
            {
               if(lpfEnumProcessModules(hProc,&hMod,sizeof(hMod),&iCbneeded) )
               {
                  iLen=lpfGetModuleBaseName(hProc,hMod,szName,MAX_PATH);
               }
            }
            CloseHandle(hProc);
            // We will match regardless of lower or upper case
#ifdef BORLANDC
            if(strcmp(strupr(szName),szToTermUpper)==0)
#else
            if(strcmp(_strupr(szName),szToTermUpper)==0)
#endif
            {
                // Process found, now terminate it
                iFound=1;
                // First open for termination
                hProc=OpenProcess(PROCESS_TERMINATE,FALSE,aiPID[i]);
                if(hProc)
                {
                    if(TerminateProcess(hProc,0))
                    {
                        // process terminated
                        CloseHandle(hProc);
                        FreeLibrary(hInstLib);
                        return 0;
                    }
                    else
                    {
                        // Unable to terminate process
                        CloseHandle(hProc);
                        FreeLibrary(hInstLib);
                        return 602;
                    }
                }
                else
                {
                    // Unable to open process for termination
                    FreeLibrary(hInstLib);
                    return 604;
                }
            }
        }
    }

    if(osvi.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS)
    {
        // Win/95 or 98 or ME
            
        hInstLib = LoadLibraryA("Kernel32.DLL");
        if( hInstLib == NULL )
            return 702;

        // Get procedure addresses.
        // We are linking to these functions of Kernel32
        // explicitly, because otherwise a module using
        // this code would fail to load under Windows NT,
        // which does not have the Toolhelp32
        // functions in the Kernel 32.
        lpfCreateToolhelp32Snapshot=
            (HANDLE(WINAPI *)(DWORD,DWORD))
            GetProcAddress( hInstLib,
            "CreateToolhelp32Snapshot" ) ;
        lpfProcess32First=
            (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
            GetProcAddress( hInstLib, "Process32First" ) ;
        lpfProcess32Next=
            (BOOL(WINAPI *)(HANDLE,LPPROCESSENTRY32))
            GetProcAddress( hInstLib, "Process32Next" ) ;
        lpfModule32First=
            (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32))
            GetProcAddress( hInstLib, "Module32First" ) ;
        lpfModule32Next=
            (BOOL(WINAPI *)(HANDLE,LPMODULEENTRY32))
            GetProcAddress( hInstLib, "Module32Next" ) ;
        if( lpfProcess32Next == NULL ||
            lpfProcess32First == NULL ||
            lpfModule32Next == NULL ||
            lpfModule32First == NULL ||
            lpfCreateToolhelp32Snapshot == NULL )
        {
            FreeLibrary(hInstLib);
            return 703;
        }
            
        // The Process32.. and Module32.. routines return names in all uppercase

        // Get a handle to a Toolhelp snapshot of all the systems processes.

        hSnapShot = lpfCreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0 ) ;
        if( hSnapShot == INVALID_HANDLE_VALUE )
        {
            FreeLibrary(hInstLib);
            return 704;
        }
        
        // Get the first process' information.
        procentry.dwSize = sizeof(PROCESSENTRY32);
        bResult=lpfProcess32First(hSnapShot,&procentry);

        // While there are processes, keep looping and checking.
        while(bResult)
        {
            // Get a handle to a Toolhelp snapshot of this process.
            hSnapShotm = lpfCreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE, procentry.th32ProcessID) ;
            if( hSnapShotm == INVALID_HANDLE_VALUE )
            {
                CloseHandle(hSnapShot);
                FreeLibrary(hInstLib);
                return 704;
            }
            // Get the module list for this process
            modentry.dwSize=sizeof(MODULEENTRY32);
            bResultm=lpfModule32First(hSnapShotm,&modentry);

            // While there are modules, keep looping and checking
            while(bResultm)
            {
                if(strcmp(modentry.szModule,szToTermUpper)==0)
                {
                    // Process found, now terminate it
                    iFound=1;
                    // First open for termination
                    hProc=OpenProcess(PROCESS_TERMINATE,FALSE,procentry.th32ProcessID);
                    if(hProc)
                    {
                        if(TerminateProcess(hProc,0))
                        {
                            // process terminated
                            CloseHandle(hSnapShotm);
                            CloseHandle(hSnapShot);
                            CloseHandle(hProc);
                            FreeLibrary(hInstLib);
                            return 0;
                        }
                        else
                        {

                            CloseHandle(hSnapShotm);
                            CloseHandle(hSnapShot);
                            CloseHandle(hProc);
                            FreeLibrary(hInstLib);
                            return 602;
                        }
                    }
                    else
                    {

                        CloseHandle(hSnapShotm);
                        CloseHandle(hSnapShot);
                        FreeLibrary(hInstLib);
                        return 604;
                    }
                }
                else
                {  
                    modentry.dwSize=sizeof(MODULEENTRY32);
                    bResultm=lpfModule32Next(hSnapShotm,&modentry);
                }
            }


            CloseHandle(hSnapShotm);
            procentry.dwSize = sizeof(PROCESSENTRY32);
            bResult = lpfProcess32Next(hSnapShot,&procentry);
        }
        CloseHandle(hSnapShot);
    }
    if(iFound==0)
    {
        FreeLibrary(hInstLib);
        return 603;
    }
    FreeLibrary(hInstLib);
    return 0;
}
/////////////////////////////////////////////////////////////////////////////////////////////
inline bool HideThread(HANDLE hThread)
{
    typedef NTSTATUS (NTAPI *pNtSetInformationThread)
                (HANDLE, UINT, PVOID, ULONG); 
    NTSTATUS Status; 

    // Get NtSetInformationThread
    pNtSetInformationThread NtSIT = (pNtSetInformationThread)
        GetProcAddress(GetModuleHandle( TEXT("ntdll.dll") ),
        "NtSetInformationThread");

    // Shouldn't fail
    if (NtSIT == NULL)
        return false; 

    // Set the thread info
    if (hThread == NULL)
        Status = NtSIT(GetCurrentThread(), 
                0x11, // HideThreadFromDebugger
                0, 0);
    else
        Status = NtSIT(hThread, 0x11, 0, 0); 

    if (Status != 0x00000000)
        return false;
    else
        return true;
}

/*void bypass()
{

	while(1)
	{
	NtTerminateThread = (_NtTerminateThread)GetProcAddress(GetModuleHandle ("ntdll.dll"),"NtTerminateThread");
	OpenThread=(lpOpenThread)GetProcAddress	(GetModuleHandle("Kernel32.dll"),"OpenThread");
	HWND hwnd= FindWindow("CrossFire","CrossFire");	 
	HANDLE h = 0;
	HANDLE hThrSuspend=0,hMThrSuspend=0;
	DWORD dwThrSuspenId=0,dwMianThreadID=0;
	DWORD PID=0;
	OpenThread=(lpOpenThread)GetProcAddress	(GetModuleHandle("Kernel32.dll"),"OpenThread");
    DWORD dwModuleBaseAddr;
	dwMianThreadID=GetWindowThreadProcessId(hwnd,&PID);
	DWORD AddressMain;
    TCHAR lpstrModuleName[MAX_PATH + 1] = {0};
int okexit;

if(PID)
{
	h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (h != INVALID_HANDLE_VALUE) {
		THREADENTRY32 te;
		te.dwSize = sizeof(te);
		hThrSuspend = OpenThread(STANDARD_RIGHTS_REQUIRED||THREAD_SUSPEND_RESUME, FALSE, dwMianThreadID);//TERMINATE
	    AddressMain = GetThreadStartAddress(hThrSuspend);
		if (Thread32First(h, &te)) {

			do {
				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
					sizeof(te.th32OwnerProcessID)&&te.th32OwnerProcessID==PID) 
				{
					dwThrSuspenId=te.th32ThreadID;
					hThrSuspend = OpenThread(STANDARD_RIGHTS_REQUIRED||THREAD_SUSPEND_RESUME, FALSE, dwThrSuspenId);//TERMINATE
					DWORD Add = GetThreadStartAddress(hThrSuspend);
					if(AddressMain != Add)
					{
	                MatchAddressToModule(PID, lpstrModuleName, Add, &dwModuleBaseAddr);
                    if(strstr(lpstrModuleName,"Crossfire.dat"))
					{
					TerminateThread(hThrSuspend,0);
					}
                    if(strstr(lpstrModuleName,"XTrapVa.dll"))
					{
					TerminateThread(hThrSuspend,0);
					okexit=1;
					}

					}
				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(h, &te));
		}
	}

}
if(okexit==1){ExitThread(0);}

	}
}
*/

int unhooking()
{


	HMODULE hLibrary=LoadLibrary("psapi.dll");
	if(hLibrary==NULL)return 0;


	EnumProcessModules = (lpEPMod) GetProcAddress (hLibrary, "EnumProcessModules");
	GetModuleFileNameEx = (lpGetModFNameEx) GetProcAddress (hLibrary, "GetModuleFileNameExA");

	MZHeader mzH2;
		PE_Header peH2;
		PE_ExtHeader peXH2;
		SectionHeader *secHdr2;
	OSVERSIONINFO ov;


	ov.dwOSVersionInfoSize = sizeof(ov);
	GetVersionEx(&ov);
	if(ov.dwMajorVersion != 5)
	{
		return 1;
	}

	if(ov.dwMinorVersion != 0 && ov.dwMinorVersion != 1)
	{
		return 1;
	}
	gWinVersion = ov.dwMinorVersion;

	if(!getNativeAPIs())
	{
		return 1;
	}

	assignACL();
	HANDLE hPhyMem = openPhyMem();
	if(hPhyMem == INVALID_HANDLE_VALUE)
		assignACL();

	hPhyMem = openPhyMem();
	if(hPhyMem == INVALID_HANDLE_VALUE)
	{
     return 1;
	}
	while(!FindWindowA("CrossFire",0))
		Sleep(2000);
	PVOID exeAddr = loadDLL("\\ntkrnlpa.exe");

	if(!exeAddr)
	{
	exeAddr = loadDLL("\\ntoskrnl.exe");
		return 1;
	}



	DWORD sdtAddr = procAPIExportAddr((DWORD)exeAddr, "KeServiceDescriptorTable");
	if(!sdtAddr)
	{
		//printf("Failed to get address of KeServiceDescriptorTable!\n");
		return 1;
	}

	if(!readPEInfo((char *)exeAddr, &mzH2, &peH2, &peXH2, &secHdr2))
	{
		//printf("Failed to get PE header of ntkrnlpa.exe!\n");
		return 1;
	}

	DWORD kernelPhyBase = getKernelBase() - PROT_MEMBASE;
	DWORD kernelOffset = kernelPhyBase - peXH2.imageBase;
	//printf("KeServiceDescriptorTable\t\t%X\n", sdtAddr + kernelPhyBase + PROT_MEMBASE);
	unsigned char *ptr = NULL;
	DWORD pAddr = sdtAddr + kernelPhyBase;
	DWORD wantedAddr = pAddr;
	DWORD len = 0x2000;
	if(mapPhyMem(hPhyMem, &pAddr, &len, (LPVOID *)&ptr))
	{
		DWORD start = wantedAddr - pAddr;
		DWORD serviceTableAddr, sdtCount; 
		DWORD wantedBytes = len - start;
		if(wantedBytes >= 4)
		{
			serviceTableAddr = *((DWORD *)(&ptr[start]));
			//printf("KeServiceDecriptorTable.ServiceTable\t%X\n", serviceTableAddr);
			if(wantedBytes >= 12)
			{
				sdtCount = *(((DWORD *)(&ptr[start])) + 2);
				//printf("KeServiceDescriptorTable.ServiceLimit\t%d\n", sdtCount);
			}
		}
		else
		{
			//printf("Sorry, an unexpected situation occurred!\n");
			return 1;
		}

		unmapPhyMem((DWORD)ptr);
		//printf("\n");

		if(sdtCount >= 300)
		{
			//printf("Sorry, an unexpected error occurred! SDT Count > 300???\n");
			return 1;
		}

		pAddr = serviceTableAddr - PROT_MEMBASE;
		wantedAddr = pAddr;
		ptr = NULL;
		len = 0x2000;
		if(mapPhyMem(hPhyMem, &pAddr, &len, (LPVOID *)&ptr))
		{
			start = wantedAddr - pAddr;
			DWORD numEntries = (len - start) >> 2;
			if(numEntries >= sdtCount)
			{
				char **nativeApiNames = NULL;
				nativeApiNames = (char **)malloc(sizeof(char *) * sdtCount);
				if(!nativeApiNames)
				{
					//printf("Failed to allocate memory for Native API name table.\n");
					return 1;
				}
				memset(nativeApiNames, 0, sizeof(char *) * sdtCount);

				PVOID ntdll = loadDLL("\\ntdll.dll");
				if(!ntdll)
				{
					//printf("Failed to load ntdll.dll!\n");
					return 1;
				}

				buildNativeAPITable((DWORD)ntdll, nativeApiNames, sdtCount);

				DWORD *serviceTable = (DWORD *)(&ptr[start]);
				DWORD *fileServiceTable = (DWORD *)((DWORD)exeAddr + wantedAddr - kernelOffset - peXH2.imageBase);
				
				DWORD fileAddr2 = (DWORD)exeAddr + getKiServiceTableAddr(exeAddr, sdtAddr, &peXH2);				
				
				if(fileAddr2 && (DWORD)fileServiceTable != fileAddr2)
				{
					//printf("Two possible addresses of KiServiceTable were found.\n\n");
					//printf("1 - %.8X\n", fileServiceTable);
					//printf("2 - %.8X (using method suggested by 90210)\n\n", fileAddr2);
					//printf("Select One (1-2): ");

					char choice[10];
					memset(choice, 0, sizeof(choice));
					fgets(choice, sizeof(choice) - 1, stdin);
					//printf("\n");					
					int intChoice = atoi(choice);
					if(intChoice < 1 || intChoice > 2)
					{
						//printf("Invalid selection!\n");
						unmapPhyMem((DWORD)ptr);
						return 1;
					}
					else if(intChoice == 2)
						fileServiceTable = (DWORD *)fileAddr2;
				}
				
				if(!IsBadReadPtr(fileServiceTable, sizeof(DWORD)) && 
				   !IsBadReadPtr(&fileServiceTable[sdtCount-1], sizeof(DWORD)))
				{
					DWORD hookCount = 0;
					for(DWORD i = 0; i < sdtCount; i++)
					{							
						if((serviceTable[i] - PROT_MEMBASE - kernelOffset) != fileServiceTable[i])
						{

							hookCount++;
						}
						
					}
					if(hookCount)
					{

						{

							for(DWORD i = 0; i < sdtCount; i++)
							{
								if((serviceTable[i] - PROT_MEMBASE - kernelOffset) != fileServiceTable[i])
								{
									serviceTable[i] = fileServiceTable[i] + PROT_MEMBASE + kernelOffset;

								}
							}
						}


					}
				}//
				else
				{


				}

			}
			unmapPhyMem((DWORD)ptr);
		}
	}
	return 0;
}
