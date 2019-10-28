/********************************************************************************************************
 * SYMANTEC:     Copyright (c) 2011-2015 Symantec Corporation. All rights reserved.
 *
 * THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC CORPORATION.  USE,
 * DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR EXPRESS WRITTEN PERMISSION OF SYMANTEC
 * CORPORATION.
 *
 * The Licensed Software and Documentation are deemed to be commercial computer software as defined in
 * FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer
 * Software - Restricted Rights" and DFARS 227.7202, Rights in "Commercial Computer Software or Commercial
 * Computer Software Documentation," as applicable, and any successor regulations, whether delivered by
 * Symantec as on premises or hosted services.  Any use, modification, reproduction release, performance,
 * display or disclosure of the Licensed Software and Documentation by the U.S. Government shall be solely
 * in accordance with the terms of this Agreement.
 ********************************************************************************************************/
// vpregistry.h

#ifndef BOOL
  typedef int BOOL;
#endif
#ifndef BYTE
  typedef unsigned char  BYTE;
#endif
#ifndef DWORD
  typedef unsigned long  DWORD;
#endif
#ifndef WORD
  typedef unsigned short WORD;
#endif
#ifndef UINT
  typedef unsigned int UINT;
#endif
#ifndef ULONG
  typedef unsigned long ULONG;
#endif
#ifndef LONG
// Not sure why this is unsigned on Netware when it's signed on Windows. jjm 11/29/2004
  typedef unsigned long LONG;
#endif
#ifndef USHORT
  typedef unsigned short int USHORT;
#endif

#undef HANDLE
#undef LPHANDLE


typedef void * PVOID;
typedef BOOL * LPBOOL;
typedef void * LPVOID;
typedef BYTE * LPBYTE;
typedef WORD * LPWORD;
typedef DWORD * LPDWORD;
typedef LONG * LPLONG;
typedef UINT * LPUINT;
typedef int * LPINT;
typedef const char * LPCSTR;
typedef char * LPSTR;
typedef DWORD FILETIME;			  // this is smaller than the windows FILETIME
typedef FILETIME *PFILETIME;
typedef PVOID HANDLE;
typedef HANDLE HKEY;
typedef HKEY * PHKEY;

// Registry access flags -- not implemented on NetWare/Linux -- provided for cross-platform friendliness
#define KEY_QUERY_VALUE         0
#define KEY_SET_VALUE           0
#define KEY_CREATE_SUB_KEY      0
#define KEY_ENUMERATE_SUB_KEYS  0
#define KEY_NOTIFY              0
#define KEY_CREATE_LINK         0
#define KEY_WOW64_32KEY         0
#define KEY_WOW64_64KEY         0
#define KEY_WOW64_RES           0
#define KEY_READ                0
#define KEY_WRITE               0
#define KEY_EXECUTE             0
#define KEY_ALL_ACCESS          0

// Types of data values:
#define REG_NONE ( 0 )   // No value type
#define REG_SZ ( 1 )   // Unicode nul terminated string
#define REG_EXPAND_SZ ( 2 )   // Unicode nul terminated string (with environment variable references)
#define REG_BINARY ( 3 )   // Free form binary
#define REG_DWORD ( 4 )   // 32-bit number
#define REG_DWORD_LITTLE_ENDIAN ( 4 )   // 32-bit number (same as REG_DWORD)
#define REG_DWORD_BIG_ENDIAN ( 5 )   // 32-bit number
#define REG_LINK ( 6 )   // Symbolic Link (unicode)
#define REG_MULTI_SZ ( 7 )   // Multiple Unicode strings
#define REG_NOTIFY_CHANGE_LAST_SET ( 100 )

#define HKEY_LOCAL_MACHINE          (( HKEY ) 0x80000002 )
#define HKEY_CURRENT_USER        (( HKEY ) 0x80000002 )

#ifndef ERROR_SUCCESS
#define ERROR_SUCCESS          0L
#endif
#define ERROR_NO_PATH          2L    // returned when a key or value specifier is invalid
#define ERROR_NO_MEMORY        14L   // when a memory allocation fails when creating a key or value or opening the registry database
#define ERROR_SEMAPHORE_IN_USE 102L  // returned from RegNotifyChangeKeyValue when the HKEY already has an associated semaphore
#define ERROR_BAD_DATABASE     1009L // Returned when the registry database has become corrupted
#define ERROR_BAD_KEY          1010L // returned when an invalid HKEY is passed into a Reg function
#define ERROR_NO_ROOM          1013L // returned when a data buffer or string passed into a function is too small to hold the data
#define ERROR_EMPTY            1015L // database file does not exists or cannot be opened
#define ERROR_NO_DATABASE      1016L // Returned when closing or saving the database and a file IO error occurs
#define ERROR_KEY_HAS_CHILDREN 1020L // returned when RegDeleteKey is called and the specified key has sub-keys

#define MAXALLOWEDSTRINGSIZE 1024

#define RegOpenKey vpRegOpenKey
#define RegCreateKey vpRegCreateKey
#define RegCreateKeyEx vpRegCreateKeyEx
#define RegDeleteKey vpRegDeleteKey
#define RegDeleteValue vpRegDeleteValue
#define RegCloseKey vpRegCloseKey
#define RegSetValueEx vpRegSetValueEx
#define RegQueryValueEx vpRegQueryValueEx
#define RegEnumValue vpRegEnumValue
#define RegEnumKeyEx vpRegEnumKeyEx
#define RegEnumKey vpRegEnumKey
#define RegFlushKey vpRegFlushKey
#define RegNotifyChangeKeyValue vpRegNotifyChangeKeyValue
#define DuplicateHandle vpDuplicateHandle
#define RegOpenKeyEx vpRegOpenKeyEx

extern "C" DWORD RegOpenKey( HKEY, LPCSTR, PHKEY );
extern "C" DWORD RegCreateKey( HKEY, LPCSTR, PHKEY );
extern "C" DWORD RegDeleteKey( HKEY, LPCSTR );
extern "C" DWORD RegDeleteValue( HKEY, LPCSTR );
extern "C" DWORD RegCloseKey( HKEY );
extern "C" DWORD RegSetValueEx( HKEY, LPCSTR, DWORD, DWORD, const BYTE*, DWORD );
extern "C" DWORD RegQueryValueEx( HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD );
extern "C" DWORD RegEnumValue( HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD );
extern "C" DWORD RegEnumKeyEx( HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME );
extern "C" DWORD RegEnumKey( HKEY, DWORD, LPSTR, DWORD );
extern "C" DWORD RegFlushKey( HKEY );
extern "C" DWORD RegCloseDatabase( BOOL );
extern "C" DWORD RegOpenDatabase( void );
extern "C" DWORD RegSaveDatabase( void );
extern "C" DWORD RegNotifyChangeKeyValue( HKEY, BOOL, DWORD, HANDLE, BOOL );
extern "C" DWORD RegOpenKeyEx( HKEY, LPCSTR, DWORD, DWORD, PHKEY );
