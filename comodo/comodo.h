/** Comodo antivirus interface structures and enumerations definitions
*   Author: Joxean Koret
*/
#ifndef COMODO_H
#define COMODO_H

#include "defs.h"

#define __cppobj
#define __fastcall
#define __usercall
#define __cdecl

typedef __int16 PRInt16;
typedef int PRInt32;
typedef unsigned int PRUint32;
typedef __int64 PRInt64;
typedef PRUint32 PRIntervalTime;
typedef int PRIntn;
typedef PRInt32 HRESULT;
typedef unsigned __int64 ULONG;
typedef void CAEFileDesc;
typedef char PRchar;
typedef unsigned __int64 PRUword;

struct __attribute__((aligned(4))) _ENGINE_REPORT_FILE_ENTRY
{
  PRchar *FileName;
  int FileNameLength;
  bool bIsNeedRemove;
};

typedef _ENGINE_REPORT_FILE_ENTRY *PENGINE_REPORT_FILE_ENTRY;

struct GUID
{
  int Data1;
  __int16 Data2;
  __int16 Data3;
  char Data4[8];
};

struct CAEEngineDispatch;

struct IAEUserCallBack
{
  char dummy;
};

struct ITarget
{
  char dummy;
};

struct ICAVStream
{
  char dummy;
};

struct IBaseComMgr
{
  char dummy;
};

struct IUnknown
{
  void *IUnknown;
};

struct IAEGetFileType
{
  char dummy;
};

struct IStringConvert
{
  char dummy;
};

struct IScanner
{
  char dummy;
};

struct IScannerMem
{
  char dummy;
};

struct CSyncLong
{
  int m_Value;
};

struct IDllMgr
{
  char dummy;
};

struct IMemMgr
{
  char dummy;
};

struct ITrace
{
  char dummy;
};

struct PRLibrary
{
  char dummy;
};

struct PRLibrary_0
{
  char dummy;
};

struct IAESignMgr
{
  char dummy;
};

enum CAECLSID
{
};

enum OWNERTYPE
{
  enum_OWNER_REALTIME = 0x0,
  enum_OWNER_ONDEMAND = 0x1,
  enum_OWNER_MEMORY = 0x2,
  enum_CALLER_RIGHTCLICK = 0x3,
};

enum SHEURLEVEL
{
  enum_SHEURLEVEL_LOW = 0x0,
  enum_SHEURLEVEL_MID = 0x1,
  enum_SHEURLEVEL_HIGH = 0x2,
};

struct __attribute__((packed)) __attribute__((aligned(1))) x1
{
  unsigned __int32 enableDosmz : 1;
  unsigned __int32 enableFirst : 1;
  unsigned __int32 enablePE32 : 1;
  unsigned __int32 enablePENew : 1;
  unsigned __int32 enableScript : 1;
  unsigned __int32 enableSimpleHeur : 1;
  unsigned __int32 enableAdvanceHeur : 1;
  unsigned __int32 enableWhite : 1;
  unsigned __int32 enableMemory : 1;
  unsigned __int32 enableSUnpack : 1;
  unsigned __int32 enableDunpack : 1;
  unsigned __int32 enableUnarch : 1;
  unsigned __int32 enableUnsfx : 1;
  unsigned __int32 enableGunpack : 1;
  unsigned __int32 enableExtra : 1;
  unsigned __int32 enbaleUnpch : 1;
  unsigned __int32 enableRules : 1;
  unsigned __int32 enableSmart : 1;
  unsigned __int32 enableReserved : 15;
};

struct __attribute__((packed)) __attribute__((aligned(2))) SCANRESULT
{
  char bFound;
  int unSignID;
  char szMalwareName[64];
  int eFileType;
  int eOwnerFlag;
  int unCureID;
  int unScannerID;
  int eHandledStatus;
  int dwPid;
  __int64 ullTotalSize;
  __int64 ullScanedSize;
  int ucrc1;
  int ucrc2;
  char bInWhiteList;
  int nReserved[2];
};

struct __attribute__((packed)) __attribute__((aligned(1))) _SCANOPTION
{
  void *UserContext;
  bool bUseHeur;
  bool bScanArchives;
  bool bScanPackers;
  bool bUseAdvHeur;
  unsigned int dwMaxFileSize;
  OWNERTYPE eOwnerFlag;
  SHEURLEVEL eSHeurLevel;
  int ScanCfgInfo;
  char szIoCharset[32];
  bool bAutoClean;
  bool bDunpackRealTime;
  bool bNotReportPackName;
  bool bWhite;
  PRUint32 dwMaxUnpackSize;
  PRUint32 dwMaxDynamicUnpackSize;
};

typedef _SCANOPTION SCANOPTION;

struct __attribute__((packed)) __attribute__((aligned(4))) THREADSCANCONTEXT
{
  int ulThreadID;
  void *m_piSrcTarget;
  void *m_pvSrcStream;
  void *m_piWhiteScanner;
  void *m_piDllMgr;
  void *m_piSignMgr;
  void *m_piFileSystem;
  void *m_piScanThreadMemMgr;
  void *m_piScanThreadTrace;
  void *m_pCAVStatistics;
};

struct vtable_403310_t
{
  signed __int64 (__fastcall *sub_402930)(__int64 *a1, __int64 a2, __int64 **a3);
  __int64 (__fastcall *sub_4028F0)(__int64 a1);
  __int64 (__fastcall *sub_402890)(__int64 a1, __int64 a2);
  int (__fastcall *sub_402790)(__int64 a1);
  __int64 (__fastcall *sub_4022C0)(void *);
  signed __int64 (__cdecl *sub_4027B0)();
  signed __int64 (__cdecl *sub_4027C0)();
  signed __int64 (__fastcall *sub_402830)(__int64 a1, __int64 a2, __int64 a3, const void *a4);
  signed __int64 (__cdecl *sub_4027D0)();
  signed __int64 (__cdecl *sub_4027E0)();
  signed __int64 (__cdecl *sub_4027F0)();
  void (__cdecl *nullsub_3)();
  void (__cdecl *nullsub_4)();
  void (__cdecl *nullsub_5)();
};

struct vtable_forCAEEngineDispatch
{
  HRESULT (__cdecl *CAEEngineDispatch_QueryInterface)(CAEEngineDispatch *a1, GUID *riid, void **ppvObject);
  ULONG (__cdecl *CAEEngineDispatch_AddRef)(CAEEngineDispatch *a1);
  ULONG (__cdecl *CAEEngineDispatch_Release)(CAEEngineDispatch *a1);
  void (__cdecl *CAEEngineDispatch_Destructor1)(CAEEngineDispatch *a1);
  void (__cdecl *CAEEngineDispatch_Destructor2)(CAEEngineDispatch *a1);
  HRESULT (__cdecl *CAEEngineDispatch_Init)(CAEEngineDispatch *a1, void *pvContext);
  HRESULT (__cdecl *CAEEngineDispatch_UnInit)(CAEEngineDispatch *a1, void *pvContext);
  HRESULT (__cdecl *CAEEngineDispatch_SetUserCallBack)(CAEEngineDispatch *a1, IAEUserCallBack *piUserCallBack);
  HRESULT (__cdecl *CAEEngineDispatch_ScanTarget)(CAEEngineDispatch *a1, ITarget *piSrcTarget, SCANOPTION *pstScanOption, SCANRESULT *pstScanResult);
  HRESULT (__cdecl *CAEEngineDispatch_ScanStream)(CAEEngineDispatch *a1, ICAVStream *piSrcStream, SCANOPTION *pstScanOption, SCANRESULT *pstScanResult);
  HRESULT (__cdecl *CAEEngineDispatch_GetBaseComponent)(CAEEngineDispatch *a1, CAECLSID eClsID, IUnknown **ppiUnknown);
  HRESULT (__cdecl *CAEEngineDispatch_CureByHandle)(CAEEngineDispatch *a1, CAEFileDesc *hSrcFileHandle, CAEFileDesc *hDstFileHandle, SCANRESULT *pstResult);
  HRESULT (__cdecl *CAEEngineDispatch_CureByTarget)(CAEEngineDispatch *a1, ITarget *piSrcTarget, CAEFileDesc *hDstFileHandle, SCANRESULT *pstResult);
  HRESULT (__cdecl *CAEEngineDispatch_Pause)(CAEEngineDispatch *a1);
  HRESULT (__cdecl *CAEEngineDispatch_Continue)(CAEEngineDispatch *a1);
  HRESULT (__cdecl *CAEEngineDispatch_Cancel)(CAEEngineDispatch *a1);
  void (__cdecl *CAEEngineDispatch_CrashReport)(CAEEngineDispatch *a1, int ModuleId, void *pvPrivateReportData, int nPrivateReportDataLength, PENGINE_REPORT_FILE_ENTRY pstRelatedFiles, int nRelatedFileCount);
};

struct IAEEngineDispatch
{
  struct vtable_forCAEEngineDispatch *baseclass_0;
};

struct CAEEngineDispatch : IAEEngineDispatch
{
  IBaseComMgr *m_piBaseComMgr;
  IAEGetFileType *m_piFileID;
  IStringConvert *m_piStringConvert;
  IScanner *m_piScanners[32];
  IUnknown *m_piUnpacks[32];
  THREADSCANCONTEXT m_stScanContext;
  IAEUserCallBack *m_piUserCallBack;
  SCANOPTION *m_pstScanOption;
  PRUword m_ulRef;
  CSyncLong m_bCancel;
  CSyncLong m_bPause;
};

struct IFrameWork
{
  struct vtable_forCFrameWork *baseclass_0;
};

struct __cppobj CFrameWork : IFrameWork
{
  IDllMgr *m_piFrameDllMgr;
  IMemMgr *m_piFrameMemMgr;
  ITrace *m_piFrameTrace;
  PRLibrary_0 *m_hPlatformModule;
  IAEUserCallBack *m_piUserCallBack;
  IAESignMgr *m_piSignMgr;
  IBaseComMgr *m_piBaseComMgr;
  PRchar *m_RootDirectory;
  int m_RootDirectoryLength;
  PRchar *m_TempPathBuffer;
  int m_TempPathBufferLength;
  PRUint32 m_ulRefCnt;
};

struct vtable_forCFrameWork
{
  HRESULT (__cdecl *CFrameWork_QueryInterface)(CFrameWork *, GUID *const riid, void **ppvObject);
  unsigned __int64 (__cdecl *CFrameWork_AddRef)(CFrameWork *);
  unsigned __int64 (__cdecl *CFrameWork_Release)(CFrameWork *);
  void (__cdecl *CFrameWork_Destructor1)(CFrameWork *);
  void (__cdecl *CFrameWork_Destructor2)(CFrameWork *);
  HRESULT (__cdecl *CFrameWork_Init)(CFrameWork *, int nRootPathSize, const PRchar *pwszRootPath, int *stCfgFormat, void *pvContext);
  HRESULT (__cdecl *CFrameWork_UnInit)(CFrameWork *, void *pvContext);
  HRESULT (__cdecl *CFrameWork_LoadScanners)(CFrameWork *, int *stCfgInfo);
  HRESULT (__cdecl *CFrameWork_CreateEngine)(CFrameWork *, IAEEngineDispatch **ppiEngineDispatch);
};

struct struct_base_component_0x20001_t
{
  _BYTE gap0[80];
  int (__fastcall *pfunc50)(__int64, __int64 *, __int64, signed __int64, signed __int64, _QWORD);
};

#endif // COMODO_H
