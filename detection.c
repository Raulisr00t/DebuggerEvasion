#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include "Structs.h" //  "PROCESSINFOCLASS" & "PEB" 

//------------------------------------------------------------------------------------------------------------------------------------------

BOOL IsDebuggerPresent2() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->BeingDebugged == 1)
		return TRUE;

	return FALSE;
}

//------------------------------------------------------------------------------------------------------------------------------------------
/*
	https://www.aldeid.com/wiki/PEB-Process-Environment-Block/NtGlobalFlag
	https://www.geoffchappell.com/studies/windows/win32/ntdll/api/rtl/regutil/getntglobalflags.htm
*/

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

BOOL IsDebuggerPresent3() {

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	if (pPeb->NtGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS))
		return TRUE;

	return FALSE;
}


//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

BOOL NtQIPDebuggerCheck() {

	NTSTATUS						STATUS = NULL;
	fnNtQueryInformationProcess		pNtQueryInformationProcess = NULL;
	DWORD64							dwIsDebuggerPresent = NULL;
	DWORD64							hProcessDebugObject = NULL;

	// getting NtQueryInformationProcess address
	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		printf("\n\t[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugPort' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugPort,
		&dwIsDebuggerPresent,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not
	if (STATUS != 0x0) {
		printf("\n\t[!] NtQueryInformationProcess [1] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (dwIsDebuggerPresent != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [1] - ProcessDebugPort Detected A Debugger \n");
		return TRUE;
	}

	// calling NtQueryInformationProcess with the 'ProcessDebugObjectHandle' flag
	STATUS = pNtQueryInformationProcess(
		GetCurrentProcess(),
		ProcessDebugObjectHandle,
		&hProcessDebugObject,
		sizeof(DWORD64),
		NULL
	);

	// if STATUS is not 0 and not 0xC0000353 (that is 'STATUS_PORT_NOT_SET')
	if (STATUS != 0x0 && STATUS != 0xC0000353) {
		printf("\n\t[!] NtQueryInformationProcess [2] Failed With Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	// if NtQueryInformationProcess returned a non-zero value, the handle is valid, which means we are being debugged
	if (hProcessDebugObject != NULL) {
		//printf("\n\t[i] NtQueryInformationProcess [w] - hProcessDebugObject Detected A Debugger \n");
		return TRUE;
	}

	return FALSE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

BOOL HardwareBpCheck() {

	CONTEXT		Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// if one of these registers is not '0', then a hardware bp is installed
	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE;

	return FALSE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

#define BLACKLISTARRAY_SIZE 5

WCHAR* g_BlackListedDebuggers[BLACKLISTARRAY_SIZE] = {
		L"x64dbg.exe",
		L"ida.exe",
		L"ida64.exe",
		L"VsDebugConsole.exe",
		L"msvsmon.exe"
};


BOOL BlackListedProcessesCheck() {

	HANDLE				hSnapShot = NULL;
	PROCESSENTRY32W		ProcEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
	BOOL				bSTATE = FALSE;


	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		printf("\n\t[!] Process32FirstW Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		for (int i = 0; i < BLACKLISTARRAY_SIZE; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_BlackListedDebuggers[i]) == 0) {
				wprintf(L"\n\t[i] Found \"%s\" Of Pid : %d\n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				break; // breaking from the for loop
			}
		}

		if (bSTATE)
			break; // breaking from the do-while loop

	} while (Process32Next(hSnapShot, &ProcEntry));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64

BOOL TimeTickCheck1() {

	DWORD	dwTime1 = NULL,
		dwTime2 = NULL;

	dwTime1 = GetTickCount64();

	dwTime2 = GetTickCount64();

	printf("\n\t[i] (dwTime2 - dwTime1) : %d \n", (dwTime2 - dwTime1));

	if ((dwTime2 - dwTime1) > 50) {
		return TRUE;
	}

	return FALSE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter

BOOL TimeTickCheck2() {

	LARGE_INTEGER	Time1 = { 0 },
		Time2 = { 0 };

	if (!QueryPerformanceCounter(&Time1)) {
		printf("\n\t[!] QueryPerformanceCounter [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!QueryPerformanceCounter(&Time2)) {
		printf("\n\t[!] QueryPerformanceCounter [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\n\t[i] (Time2.QuadPart - Time1.QuadPart) : %d \n", (Time2.QuadPart - Time1.QuadPart));

	if ((Time2.QuadPart - Time1.QuadPart) > 100000) {
		return TRUE;
	}

	return FALSE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

// https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak

BOOL DebugBreakCheck() {

	__try {
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
		return FALSE;
	}

	return TRUE;
}

//------------------------------------------------------------------------------------------------------------------------------------------

BOOL OutputDebugStringCheck() {

	SetLastError(1);
	OutputDebugStringW(L"MalDev Academy");

	if (GetLastError() == 0) {
		return TRUE;
	}

	return FALSE;
}
#define BLACKLISTEDAPP_SIZE 6

WCHAR* g_BlackListedApps[BLACKLISTEDAPP_SIZE] = {
	L"x64dbg",
	L"IDA",
	L"IDA64",
	L"VsDebugConsole.exe",
	L"ollydbg",
	L"WinDbg"
};

BOOL StartsWith(const WCHAR* str, const WCHAR* prefix) {
	while (*prefix) {
		if (*prefix++ != *str++) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
	WCHAR windowTitle[256];
	GetWindowTextW(hwnd, windowTitle, sizeof(windowTitle) / sizeof(WCHAR));

	if (IsWindowVisible(hwnd) && wcslen(windowTitle) != 0) {
		for (int i = 0; i < BLACKLISTEDAPP_SIZE; i++) {
			if (StartsWith(windowTitle, g_BlackListedApps[i]) || wcscmp(windowTitle, g_BlackListedApps[i]) == 0) {
				wprintf(L"Blacklisted App Found: %s\n", windowTitle);
				return FALSE;
			}
		}
	}
	return TRUE; 
}

BOOL isBlacklistedApps() {
	return EnumWindows(EnumWindowsProc, 0);
}

//------------------------------------------------------------------------------------------------------------------------------------------

int main() {

	printf("[#] Press <Enter> To Start ... ");
	getchar();

	//----------------------------------------------
	//	tech 1 :

	printf("\n[#] Running IsDebuggerPresent ... ");
	if (IsDebuggerPresent())
		printf("<<!>> IsDebuggerPresent detected a debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 2 :

	printf("\n[#] Running IsDebuggerPresent2 ... ");
	if (IsDebuggerPresent2())
		printf("<<!>> IsDebuggerPresent2 Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 3 :

	printf("\n[#] Running IsDebuggerPresent3 ... ");
	if (IsDebuggerPresent3())
		printf("<<!>> IsDebuggerPresent3 Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 4 :

	printf("\n[#] Running NtQIPDebuggerCheck ... ");
	if (NtQIPDebuggerCheck())
		printf("<<!>> NtQIPDebuggerCheck Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 5 :

	printf("\n[#] Running HardwareBpCheck ... ");
	if (HardwareBpCheck())
		printf("<<!>> HardwareBpCheck Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 6 :

	printf("\n[#] Running BlackListedProcessesCheck ... ");
	if (BlackListedProcessesCheck())
		printf("<<!>> BlackListedProcessesCheck Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 7 :

	printf("\n[#] Running TimeTickCheck1 ... ");
	if (TimeTickCheck1())
		printf("<<!>> TimeTickCheck1 Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 8 :

	printf("\n[#] Running TimeTickCheck2 ... ");
	if (TimeTickCheck2())
		printf("<<!>> TimeTickCheck2 Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 9 :

	printf("\n[#] Running DebugBreakCheck ... ");
	if (DebugBreakCheck())
		printf("<<!>> DebugBreakCheck Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//----------------------------------------------
	//	tech 10 :

	printf("\n[#] Running OutputDebugStringCheck ... ");
	if (OutputDebugStringCheck())
		printf("<<!>> OutputDebugStringCheck Detected A Debugger <<!>> \n");
	else
		printf("[+] DONE \n");

	//-----------------------------------------------
	// tech 11 :

	printf("\n[#] Running isAppinWindowTitle ... ");
	if (!isBlacklistedApps) {
		printf("<<!>> Detected Debugger in Window Title <<!>> \n");
	}
	else {
		printf("[+] DONE \n");
	}
	printf("\n[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}
