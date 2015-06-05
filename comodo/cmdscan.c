/** Alternative version of the Comodo's "cmdscan" command line scanner.
*   Only for research purposes.
*   Author: Joxean Koret
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <libgen.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "comodo.h"

//----------------------------------------------------------------------
// Function declarations
int main(int argc, char **argv, char **envp);
void uninit_framework();
int scan_stream(char *src, char verbosed, int *scanned_files, int *virus_found);
int IFrameWork_CreateInstance();
void dlclose_framework();
void load_framework();
void scan_directory(char *src, char verbose, int *scanned_fils, int *virus_found);

//----------------------------------------------------------------------
// Typedef declarations
typedef int (__fastcall *FnCreateInstance_t)(
    _QWORD,
    _QWORD,
    _QWORD,
    CFrameWork **);

//----------------------------------------------------------------------
// Data declarations
char *optarg;
char *src = NULL;
char verbose;
char quiet = 0;
__int64 g_base_component_0x20001;
__int64 g_user_callbacks;
CAEEngineDispatch *g_Engine;
CFrameWork *g_FrameworkInstance;
FnCreateInstance_t FnCreateInstance;
void *hFrameworkSo;
vtable_403310_t *vtable_403310;

//----------------------------------------------------------------------
void usage(char *prog_name, int exit_code)
{
  printf(
    "USAGE: %s -s [FILE] [OPTION...]\n"
    "-s: scan a file or a directory\n"
    "-q: quite mode\n"
    "-v: verbose mode, display more detailed output\n"
    "-h: this help screen\n", prog_name);
  exit(exit_code);
}

//----------------------------------------------------------------------
int main(int argc, char **argv, char **envp)
{
  int opt;
  int scanned_files;
  int virus_found;

  scanned_files = 0;
  virus_found = 0;
  while ( 1 )
  {
    opt = getopt(argc, argv, "s:vhq");
    if ( opt == -1 )
      break;
    switch ( opt )
    {
      case 's':
        if ( access(optarg, 0) )
          usage(argv[0], 1);

        src = realpath(optarg, NULL);
        if ( src == NULL )
        {
          perror("realpath");
          exit(1);
        }
        break;
      case 'v':
        verbose = 1;
        break;
      case 'q':
        quiet = 1;
        break;
      case 'h':
        usage(argv[0], 0);
        break;
    }
  }

  if ( !src )
    usage(argv[0], 1);

  load_framework();
  IFrameWork_CreateInstance();

  if ( verbose )
    fwrite("-----== Scan Start ==-----\n", 1uLL, 0x1BuLL, stdout);

  struct stat st;
  lstat(src, &st);
  if ( S_ISDIR(st.st_mode) )
    scan_directory(src, verbose, &scanned_files, &virus_found);
  else
    scan_stream(src, verbose, &scanned_files, &virus_found);

  if ( verbose )
    fwrite("-----== Scan End ==-----\n", 1uLL, 0x19uLL, stdout);

  if ( virus_found && !quiet )
  {
    printf("Final number of Scanned Files: %d\n", scanned_files);
    printf("Final number of Found Viruses: %d\n", virus_found);
  }

  uninit_framework();
  dlclose_framework();
  return 0;
}

//----------------------------------------------------------------------
void uninit_framework()
{
  g_base_component_0x20001 = 0;
  if ( g_Engine )
  {
    g_Engine->baseclass_0->CAEEngineDispatch_Cancel(g_Engine);
    g_Engine->baseclass_0->CAEEngineDispatch_UnInit(g_Engine, 0);
    g_Engine = 0;
  }
  if ( g_FrameworkInstance )
  {
    g_FrameworkInstance->baseclass_0->CFrameWork_UnInit(g_FrameworkInstance, 0);
    g_FrameworkInstance = 0;
  }
}

//----------------------------------------------------------------------
// Automatically generated from a (crappy) Python script, this is why
// the switch is not ordered.
const char *get_scanner_name(int id)
{
  switch ( id )
  {
    case 15:
      return "UNARCHIVE";
    case 28:
      return "SCANNER_PE64";
    case 27:
      return "SCANNER_MBR";
    case 12:
      return "ENGINEDISPATCH";
    case 7:
      return "UNPACK_STATIC";
    case 22:
      return "SCANNER_EXTRA";
    case 29:
      return "SCANNER_SMART";
    case 16:
      return "CAVSEVM32";
    case 6:
      return "SCANNER_SCRIPT";
    case 9:
      return "SIGNMGR";
    case 21:
      return "UNPACK_DUNPACK";
    case 13:
      return "SCANNER_WHITE";
    case 24:
      return "SCANNER_RULES";
    case 8:
      return "UNPACK_GUNPACK";
    case 10:
      return "FRAMEWORK";
    case 3:
      return "SCANNER_PE32";
    case 5:
      return "MEMORY_ENGINE";
    case 23:
      return "UNPATCH";
    case 2:
      return "SCANNER_DOSMZ";
    case 4:
      return "SCANNER_PENEW";
    case 0:
      return "Default";
    case 17:
      return "CAVSEVM64";
    case 20:
      return "UNSFX";
    case 19:
      return "SCANNER_MEM";
    case 14:
      return "MTENGINE";
    case 1:
      return "SCANNER_FIRST";
    case 18:
      return "SCANNER_HEUR";
    case 26:
      return "SCANNER_ADVHEUR";
    case 11:
      return "MEMTARGET";
    case 25:
      return "FILEID";
    default:
      return "Unknown";
  }
}

//----------------------------------------------------------------------
void scan_directory(char *dirname, char verbose, int *scanned_files, int *virus_found)
{
  DIR *d_fh;
  d_fh = opendir(dirname);
  if ( d_fh == NULL )
  {
    fprintf(stderr, "Couldn't open directory: %s\n", dirname);
    perror("opendir");
    return;
  }

  struct dirent *entry;
  while ( ( entry=readdir(d_fh) ) != NULL )
  {
    if ( entry->d_name[0] != '.' )
    {
      char longest_name[4096];
      snprintf(longest_name, sizeof(longest_name)-1, "%s/%s", dirname, entry->d_name);
      if ( entry->d_type == DT_DIR )
        scan_directory(longest_name, verbose, scanned_files, virus_found);
      else
        scan_stream(longest_name, verbose, scanned_files, virus_found);
    }
  }

  closedir(d_fh);
}

//----------------------------------------------------------------------
int scan_stream(char *src, char verbosed, int *scanned_files, int *virus_found)
{
  struct_base_component_0x20001_t *base_component_0x20001;
  int result;
  HRESULT err;
  SCANRESULT scan_result;
  SCANOPTION scan_option;
  ICAVStream *inited_to_zero;

  memset(&scan_option, 0, sizeof(SCANOPTION));
  memset(&scan_result, 0, sizeof(SCANRESULT));
  scan_option.ScanCfgInfo = -1;
  scan_option.bScanPackers = 1;
  scan_option.bScanArchives = 1;
  scan_option.bUseHeur = 1;
  scan_option.bDunpackRealTime = 1;
  scan_option.bUseAdvHeur = 1;
  scan_option.bNotReportPackName = 0;
  scan_option.eSHeurLevel = enum_SHEURLEVEL_HIGH;
  base_component_0x20001 = *(struct_base_component_0x20001_t **)g_base_component_0x20001;
  scan_option.dwMaxFileSize = 0x2800000;
  scan_option.eOwnerFlag = enum_OWNER_ONDEMAND;
  scan_option.bDunpackRealTime = 1;
  scan_option.bNotReportPackName = 0;

  inited_to_zero = 0;
  result = base_component_0x20001->pfunc50(
             g_base_component_0x20001,
             (__int64 *)&inited_to_zero,
             (__int64)src,
             1LL,
             3LL,
             0);
  err = result;
  if ( result >= 0 )
  {
    err = g_Engine->baseclass_0->CAEEngineDispatch_ScanStream(g_Engine, inited_to_zero, &scan_option, &scan_result);
    if ( err >= 0 )
    {
      (*scanned_files)++;
      if ( scanned_files )
      {
        if ( scan_result.bFound )
        {
          printf("%s ---> Malware: %s\n", src, scan_result.szMalwareName);
          if ( scan_result.unSignID )
            printf("Signature ID: 0x%x\n", scan_result.unSignID);
          if ( scan_result.unScannerID )
            printf("Scanner     : %d (%s)\n", scan_result.unScannerID, get_scanner_name(scan_result.unScannerID));
          if ( scan_result.ullTotalSize ) 
            printf("Total size  : %lld\n", scan_result.ullTotalSize);
          if ( scan_result.ullScanedSize )
            printf("Scanned size: %lld\n", scan_result.ullScanedSize);
          if ( scan_result.ucrc1 || scan_result.ucrc2 )
            printf("CRCs        : 0x%x 0x%x\n", scan_result.ucrc1, scan_result.ucrc2);
          result = fflush(stdout);
        }
        else
        {
          if ( !quiet || scan_result.bInWhiteList )
          {
            printf("%s ---> Not Virus\n", src);
            if ( scan_result.bInWhiteList )
              printf("INFO: The file is white-listed.\n");
            result = fflush(stdout);
          }
        }
      }
    }
  }
  if ( scan_result.bFound )
  {
    if ( err >= 0 )
      (*virus_found)++;
  }
  return result;
}

//----------------------------------------------------------------------
int IFrameWork_CreateInstance()
{
  char *cur_dir;
  CFrameWork *hFramework;
  int cur_dir_len;
  CFrameWork *hInstance;
  int *v8;
  int *maybe_flags;

  hInstance = 0;
  if ( FnCreateInstance(0, 0, 0xF0000, &hInstance) < 0 )
  {
    fwrite("CreateInstance failed!\n", 1uLL, 0x17uLL, stderr);
    exit(1);
  }

  BYTE4(maybe_flags) = 0;
  LODWORD(maybe_flags) = -1;
  g_FrameworkInstance = hInstance;
  cur_dir = get_current_dir_name();
  hFramework = g_FrameworkInstance;
  cur_dir_len = strlen(cur_dir);
  if ( hFramework->baseclass_0->CFrameWork_Init(hFramework, cur_dir_len + 1, cur_dir, maybe_flags, 0) < 0 )
  {
    fwrite("IFrameWork Init failed!\n", 1uLL, 0x18uLL, stderr);
    exit(1);
  }
  free(cur_dir);
  LODWORD(v8) = -1;
  BYTE4(v8) = 0;
  if ( g_FrameworkInstance->baseclass_0->CFrameWork_LoadScanners(g_FrameworkInstance, v8) < 0 )
  {
    fwrite("IFrameWork LoadScanners failed!\n", 1uLL, 0x20uLL, stderr);
    exit(1);
  }
  if ( g_FrameworkInstance->baseclass_0->CFrameWork_CreateEngine(g_FrameworkInstance, (IAEEngineDispatch **)&g_Engine) < 0 )
  {
    fwrite("IFrameWork CreateEngine failed!\n", 1uLL, 0x20uLL, stderr);
    exit(1);
  }
  if ( g_Engine->baseclass_0->CAEEngineDispatch_GetBaseComponent(
         g_Engine,
         (CAECLSID)0x20001,
         (IUnknown **)&g_base_component_0x20001) < 0 )
  {
    fwrite("IAEEngineDispatch GetBaseComponent failed!\n", 1uLL, 0x2BuLL, stderr);
    exit(1);
  }
  return 0;
}

//----------------------------------------------------------------------
void dlclose_framework()
{
  if ( hFrameworkSo )
    dlclose(hFrameworkSo);
}

//----------------------------------------------------------------------
void load_framework()
{
  chdir("/opt/COMODO");
  hFrameworkSo = dlopen("./libFRAMEWORK.so", 1);
  if ( !hFrameworkSo )
  {
    fprintf(stderr, "Error loading libFRAMEWORK: %s\n", dlerror());
    exit(1);
  }

  FnCreateInstance = (FnCreateInstance_t)dlsym(hFrameworkSo, "CreateInstance");
  if ( !FnCreateInstance )
  {
    fprintf(stderr, "%s\n", dlerror());
    exit(1);
  }
}
