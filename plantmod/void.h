#define hHandle	GetCurrentProcess()

#define Section_1	0x1
#define Section_2	0x155
#define Section_3	0x3FD
#define Section_4	0x6A5
#define Section_5	0x551
#define Section_6	0x2A9

#define Section_s1	0xC0
#define Section_s2	0xC4
#define Section_s3	0xCC
#define Section_s4	0xD4
#define Section_s5	0xD0
#define Section_s6	0xC8

#define DATA_1	276
#define DATA_2	300
#define DATA_3	348
#define DATA_4	396
#define DATA_5	372
#define DATA_6	324

#define SlkMemoryAudition	0x0121CA80
#define StartGame	0x011E1AD0
#define GameType	0x0121CA59
#define Character	0x1245828
#define BUCOUNT	0x11EFF64
#define dwPageNV	0x11E1804
#define	YARD	0x121CA4E
#define BeatUpPerfectScore	0x0097E9B4 //score space
#define ScoreNormal	0x0096C8BD //00 80 40 00 00 00 40 00  00 C0 3F
#define HackPerfectNormal	0x0096C873 // 3F 9A 99 59 3F 14 AE 47  3F 00 00 00 00 00 00 80

/*function global*/
bool boolOnOff();
int choosereturn();
int AutoBUMain();
void HideCharacter();
int subOGG();
void killThreadXTrap();
int __stdcall FSOUND_Stream_Open (const char *name_or_data, int mode, int offset, int length);
void ImportAddressHook(PROC main, PCSTR dllMain, PCSTR ProcName, LPCSTR lpModuleName);
void __stdcall WriteMemoryProcess(DWORD dwAddress, LPCVOID buffer, size_t size, SIZE_T *size_);
bool fexists(const char *filename);
int ForgeHook(PROC pfnNew, PCSTR pszHookModName,PCSTR pszMessageBoxName, byte **Buffer);
/*---------------*/