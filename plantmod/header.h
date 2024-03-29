#include "variable.h"
#include "anti.h"
class ClsBox
{
public:
	DWORD Address;
	DWORD ShowFps_Address;
	DWORD AddressBaseCharacter;
	DWORD AddressFreedom;
	DWORD m_csvbackup;
	DWORD AddressCsvBackup;
	DWORD bu_base;
	LPVOID lpBaseAddress_Anti;
	LPVOID Protect_anti;
	
	char GameEvent[100];
	char GameAccount[100];
	char SONG_TITLE[100];
	char ARTIST_TITLE[100];
	float BPM_TITLE;
	char *GAME_TYPE_GLOBAL;
	const char *GUITAR_TBM;
	char *GetTbmFilePath;
	char *GetTbmFileGuitar;
	char *TbmBGM;
	char *TbmNormalFile;

	int NPC_Number;
	int player_score[6];
	int order[6];
	int PLAY;
	int OggS;
	int pAddress;
	int pCharacter;
	int pFreedom;
	int m_hidenum[6];
	int length;
	int status;
	int room_status;
	int countdown;

	HWND hwnd;
	HWND hWnd;
	DWORD result;
	HANDLE thread_1;
	HANDLE thread_2;
	HANDLE thread_3;
	HANDLE thread_4;

	int countsend_1[6];
	int countsend_2[6];
	int countsend_3[6];
	int countsend_4[6];
	int countsend_5[6];
	int countsend_6[6];

	bool DATA051;
	LPVOID DATA_051ACV;
	
	void set_data();
	BOOL RM(LPCVOID lpAddress, LPVOID buffer, SIZE_T size, SIZE_T *lpSize);
	int winlose(char *account, int coins, char *winlose);
	char *SetInfo(char *file_name);
	char *GetInfo();
	char *MedalInfo();
	void ClsBox::Ladder(char *SongName, char *UserName, char *account,
	int cperfect, int cgreat, int ccool, int cbad, int cmiss, int cscore, int ccombo, int cBUxMax);
	void KeyVirtual();
	void SendBonus(char *account, int color, int medal, int hide_bonus);
	void ClsBox::HoanVi(int &a, int &b);
	void ClsBox::InsertionSort(int A[], int n);
	int roomstatus();
	void addserver(char *account, int room_number, int type, int count);
	void checkban(char *title);
	int MConnect(char *music, char *dest);
	int ErrorReport(const char *error);
	int EventConnect();
	void CreateFolder(const char *path);
	BOOL SetScreenResolution(int nWidth, int nHeight);
	BOOL ClsBox::RestoreScreenResolution(VOID);
	void LoadChance(int num);
	void SetChance(int num);
	void FrameEXP();
	void mySprintf(char *buffer, const char *format, ...);
	int GetMusicStatus(int OggS);
	char *GetGameType();
	int FileExist(char *FileName);
	char *GetTbmFile();
	int ReturnHackAnti();
	void LoadTitle();
	char *LoadMusicResource(const char *TbmFile);
	HWND GETHWND();
	HINSTANCE MyShellExecute(HWND hwnd,LPCTSTR lpOperation,LPCTSTR lpFile, LPCTSTR lpParameters,LPCTSTR lpDirectory,INT nShowCmd);
	BOOL __stdcall MyTerminateProcess(HANDLE hProcess, UINT uExitCode);
	int __stdcall MyMessageBox(LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

	int CheckConnect();
	void DecodeACV(const char *Input);
	char *replace(const char *s, const char *old, const char *newstr);
	void ImportAddressHook(PROC main, PCSTR dllMain, PCSTR ProcName, LPCSTR lpModuleName);
	void CallReplace(DWORD DiaChiLenhCall, DWORD DiaChiHamMoi);
	int FindAndWriteBytes(char *value, DWORD dwStart, DWORD dwEnd);
	DWORD AutoFindAddress(char *value, DWORD dwStart, DWORD dwEnd);
	DWORD AutoFindBytes(char *lpBuffer, DWORD dwStart, DWORD dwEnd);
	void __stdcall WriteMemoryProcess(DWORD dwAddress, LPCVOID buffer, size_t size, SIZE_T *size_);
};
struct stTEXT{
	char *text;
};
struct stAnti{
	DWORD address;
};
struct stDATA{
	int c;
	LPCSTR lpString;
};
static struct stAnti	stVariable[]={
	(DWORD)aEmoticon,
	(DWORD)aNormal,
	(DWORD)aBeatup,
	(DWORD)aOnetwo,
	(DWORD)aSpace,
	(DWORD)aBlock,
	(DWORD)aSlang,
	(DWORD)aBattle,
	(DWORD)aGuitar,
	(DWORD)BEATUPPERFECT,
	(DWORD)SLK_DATA,
	(DWORD)KEYMAP_1_1,
	(DWORD)KEYMAP_4_1,
	(DWORD)KEYMAP_7_1,
	(DWORD)KEYMAP_9_1,
	(DWORD)KEYMAP_6_1,
	(DWORD)KEYMAP_3_1,
	(DWORD)KEYMAP_1_2,
	(DWORD)KEYMAP_4_2,
	(DWORD)KEYMAP_7_2,
	(DWORD)KEYMAP_9_2,
	(DWORD)KEYMAP_6_2,
	(DWORD)KEYMAP_3_2,
	(DWORD)BEATUPDATA, 
	(DWORD)NORMALDATA
};
/*change name, text, blah blah*/
static struct stTEXT roomName[]={
	"CuÌng khãÒng ðiònh ðãÒng câìp AU!",
	"Không coì chôÞ cho gian lâòn õÒ ðây!~",
	"Giây phuìt caÒm xuìc thãng hoa!~",
	"MiÌnh cuÌng khiêu vuÞ nheì?~",
	"HoÌa miÌnh cuÌng nhiòp ðiêòu AU!",
	"CuÌng giaÒi toÒa cãng thãÒng nheì!~",
	"HaÞy nhaÒy cuÌng chuìng tôi",
	"CuÌng ðêìn ðây! Chuìng ta chõi AU naÌo!",
	"Ai laÌ truÌm Perfect?",
	"Ðêìn môòt ngaÌy naÌo ðoì, tôi seÞ không bao giõÌ Miss!"
};
static struct stTEXT DATA_GUITAR[]={
	"null"
};
static struct stTEXT DATA_TEXT[]={
	"†iêÒu¯®¯†ýÒ",
	"HPF•T.hýõng™",
	"Beat Up II",
	"A´STAR—Ørï™ ",
	"Audition - 1,2 Fiesta"
};
static struct stTEXT DATA_CHANGE[]={
	"TôÒng ÐiêÌu HaÌnh AuPatch",
	"QUAÒN TRIò VIÊN AUPATCH - LYì MAòC SÂÌU",
	"Audition Patch channel",
	"QUAÒN TRIò VIÊN AUPATCH - ORI - KIìCH MIÌNH THÝÒ ÐI, BAòN SEÞ THÂìY HÂòU QUAÒ NÃòNG NÊÌ Ê CHÊÌ NHA BÂY BÊÌ!!!!",
	//--Thi sinh
	"Không phaÒi daòng výÌa ðâu"
};
static struct stTEXT ATHack[]={
	"Kernel Detective",
	"Cheat Engine",
	"Keksmiz Plus",
	"Keksmiz",
	"keksmiz",
	"Auto Audition",
	"Auto party",
	"Auto BeatUp",
	"modz",
	"Modz",
	"XVI32",
	"CMModz",
	"FBU"
};
static struct stTEXT	DLL_ANTI[]={
	"kdfindme.dll",
	"KeksmizModule.dll",
	"PVModz.dll",
	"TSModz.exe",
	"hid.dll"
};
static struct stTEXT	ERROR_RESULT[]={
	"Vui long dang ky tham gia tai http://aupatch.com\nRegister, please",
	"Baòn coì muôìn kick %s",
	"Cham dut ket noi may chu Audition Patch!",
	"TBM not found!",
	"BOOT EXP",
	"Ban khong phai thi sinh tham gia event!",
	"Tai khoang da het han tham gia\nvui long gia han"
};
static struct stTEXT	LOAD_DATA_NOTKICK[]={
	"†iêÒu¯®¯†ýÒ",
	"No1_Hnnp",
	"GM_[M]Patch",
	"Meo::Meo",
	"A´STAR—Göñ™",
	"A´STAR—Ørï™ ",
	"HPF•T.hýõng™"
};
static struct stTEXT	ADMIN_ACCOUNT[]={
	"mastermpatch",
	"thatkiem3009",
	"no1patch"
};
static struct stTEXT	ADMIN_KICK[]={
	"thatkiem3009",
	"mastermpatch"
};
static struct stTEXT	NPC_NAME[]={
	"mastermpatch"
};