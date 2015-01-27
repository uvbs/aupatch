//#define	WinMainAudition	0x0041A3B0 //address of winmain
#define	CSVFUNCTION		0x44FD20 //address of CSV Function
//#define OffsetWinmain	0x008E61B9 //address call winmain
#define	OffsetCSV		0x00854494//aGuitarNoteData -> up 12 line
#define HOOKAUDITION	0x006CE960
#define OffsetPointer	0x0043EDD0
#define	OffsetDirectDraw	0x004416F0
#define	OffsetCallFPS		0x00714736

#define PASSWORD_OFFSET	0x3AF

#define	LOAD_MEMORY		(0x00020000 | 0x00008000)
#define	DWSTART			0x00800000
#define	DWEND			0x00A00000
#define	DWSTARTB		0x00500000
#define	DWENDB			0x00800000
#define SONGTITLE		0x104 + 28
#define ARTISTTITLE		0x203 + 28
#define BPMTITLE		0x304 + 28

#define BBCOMBOPOINTER	0x5F2C
#define Count1	276
#define Count2	300
#define Count3	348
#define Count4	396
#define Count5	372
#define Count6	324
#define Section_s1	0xC0
#define Section_s2	0xC4
#define Section_s3	0xCC
#define Section_s4	0xD4
#define Section_s5	0xD0
#define Section_s6	0xC8

#define ACCOUNT_AUDITION		0x01269557 /*var 1 of aRealgaia down 3 line*/
#define BASE_INFOMATION			0x0124FCC8 /*aGameFpsDFrames down 8 line*/
#define SLK_DATA				0x0128B8A0 /*aScriptDS_beat_ down 3 line*/
#define GAME_TYPE				0x0128B879 /*aTextureGuiBS_0 var 1 -> up 8 line*/
#define	YARD					0x0128B86E /*aV_10 var 1 -> down 6 line*/
#define aEmoticon				0x00997228
#define aNormal					0x00997540
#define aBeatup					0x009972E8
#define aOnetwo					0x00997314
#define aSpace					0x009971F8
#define aBlock 					0x009971AC
#define aSlang 					0x0099738C
#define aBattle					0x00997374
#define	aGuitar					0x009972D0
#define	ROOM_NAME				0x0128B65E /*Find : aSSize16Out1S : up 2 line*/
#define	ROOM_NUMBER				(ROOM_NAME - 2)
#define	BEATUP_NOTE				0x009E6628 /*aADD*/
#define	BEATUP_SCORE			0x009E64E0 /*90 01 00 00 C8 00 00 00*/
#define	BEATUP_SPACE_SCORE		0x009E64F4 /*D0 07 00 00 DC 05 00 00  E8 03 00 00 F4 01 00 00*/
#define	LEFT_LANE				0x009E65EC /*b3 eb c6 ae b6 f3 c0 ce 4c 5f 33*/
#define	RIGHT_LANE				0x009E65E0
#define	PASSWORD2				0x011B8E6C /*aTextureGuiMa_4 -> up 12 line*/
#define CHAT					0x01239170 //Find : aFontS : down 13 line/
#define	BEATUPPERFECT			0x009E64A0/*05 00 00 00 0F 00 00 00  1B 00 00 00 28 00 00 00*/
#define CHARACTER_NAME			0x01269458 //aCannot_join_to up 6 line
#define BUCOUNT					0x0125EC54//Find : aRhythmholicBt_ (var number 4 )/
#define STARTGAME				0x0124FF94//Find : aGuiMsgback : down 65 line/ ( byte )
#define	CTRLTAB					0x012520AC //Find : aBallroomSilhou -> up 14 line
#define	BEATUPDATA				0x011F2214
#define	NORMALDATA				0x011F2198
#define	GUITARNOTE				0x009E52D0 //a_gt_D_csv
#define Character				0x012B582C//Find : aTextureGuiB_10 : up 16 line/
#define	DELNOTICE				0x009E66D4

#define CHARACTERHIDE	4
#define CHARACTERSHOW	2
#define CHARACTERKICK	1

#define	VIRTUALPROTECT			"%x fail to protect %d"
#define	ROOMNAME				"AUPATCH.COM - Chiêìn cuÌng anh em ;cuoi"
#define	NPC_INFO				"Giêìt BOSS %s [thãìng : +%d, thua -%d]"
#define	INFO_PLAY				"%s ðang chõi Audition Patch"
#define	INFO_WIN				"THÃìNG : %s ðýõòc +%d COIN"
#define	INFO_LOSE				"THUA : %s biò -%d COIN"
#define	SERVERSAVE				"audition_patch//%s"
#define	BGMPATH					"audition_patch//bgm//%s"
#define HTTPADD					"reg/nap/cal.php?a=%s&r=%d&t=%d&c=%d"
#define HTTPBAN					"reg/nap/ban.php?ac=%s&hack=%s"
#define SERVERMUSIC				"http://123.30.241.136/music/hnnp/%s"
#define	ERRORREPORT				"/error"
#define	EVENT_ROOM				"Event"
#define	SERVERGAME				"123.30.241.136"
#define HTTPSERVER				"reg/register/check.php?name=%s&pass=%s"
#define HTTPEVENT				"reg/nap/checkevent.php?name=%s"
#define	HTTPINFO				"reg/nap/getinfo.php?account=%s"
#define	MEDALINFO				"reg/nap/medal.php"
#define WINLOSE					"reg/nap/npc.php?acc=%s&c=%d&sub=%s"
#define	SET_NAME_FILE			"http://123.30.241.136/%s"
#define HTTPREPORT				"reg/nap/report.php?a=%s&r=%s"
#define	HTTPREGISTER			"http://123.30.241.136"
#define	HTTPDAY					"date"
#define	HTTPOKEY				"playpatchok"
#define	EVENTOKEY				"event"
#define	FINDSTRING				"A%d%d"
#define	REPLACESTRING			"B%d%d"
#define FREEDOMSTRING			"Beat Up II"
#define	OLDACV					"data/112.acv"
#define NEWACV					"aupatch.acv"
#define	OLDLOC					"script/vietname.loc"
#define DATAFILE				"data.dta"
#define NEWLOC					"vietname.loc"
//#define sBattle					"script/1attleparty.slk"
//#define sBeatUp					"script/1eatup.slk"
//#define sNormal					"script/1111.slk"
//#define sOnetwo					"script/1netwo.slk"
//#define sSlang					"script/1lang.slk"
//#define sBlock					"script/1lockbeat.slk"
//#define sSpace					"script/1pacepangpang.slk"
//#define	sGuitar					"script/guitarmusic.slk"
//#define guitar_note				"_at_%d.csv"

#define GUITAR			124646
#define BEATUP4			105885
#define BEATUP6			104857
#define ONETWOEASY		106142
#define ONETWOHARD		104343
#define BLOCKBEAT		109997
#define SPACEPANGPANG	125931
#define	NORMALPLAY		66050

#define Score_s1	(0xC0 + 0x4)
#define Score_s2	(0xC4 + 0x4)
#define Score_s3	(0xCC + 0x4)
#define Score_s4	(0xD4 + 0x4)
#define Score_s5	(0xD0 + 0x4)
#define Score_s6	(0xC8 + 0x4)
