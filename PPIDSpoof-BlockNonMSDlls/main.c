#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

// Define the process properties
#define SPAWNPROCESS "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
#define COMMANDLINE "\"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\" --no-startup-window --win-session-start /prefetch:5"
#define WORKINGDIRECTORY "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\114.0.1823.82\\"

// Define the parent process to spoof
#define PARENTPROCESS L"Notepad.exe"

// This function will return the integrity level of a process
LPCWSTR getIntegrityLevel(HANDLE hProcess) {
	HANDLE hToken;
	OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);

	DWORD cbTokenIL = 0;
	PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
	GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &cbTokenIL);
	pTokenIL = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LPTR, cbTokenIL);
	GetTokenInformation(hToken, TokenIntegrityLevel, pTokenIL, cbTokenIL, &cbTokenIL);

	DWORD dwIntegrityLevel = *GetSidSubAuthority(pTokenIL->Label.Sid, 0);

	if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
		return L"LOW";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
		return L"MEDIUM";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
		return L"HIGH";
	}
	else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
		return L"SYSTEM";
	}
}

// This function will return the PID of a process
DWORD getPPID(LPCWSTR processName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process)) {
		do {
			if (!wcscmp(process.szExeFile, processName)) {
				HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
				if (hProcess) {
					LPCWSTR integrityLevel = NULL;
					integrityLevel = getIntegrityLevel(hProcess);
					if (!wcscmp(integrityLevel, L"MEDIUM")) {
						break;
					}
				}
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return process.th32ProcessID;
}

// This function will spawn a process with the given parameters
BOOL SpawnProcess(HANDLE hParentProcess, LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	STARTUPINFOEXA			SiEx = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };
	SIZE_T					sAttrSize = NULL;
	PVOID					pAttrBuf = NULL;

	// Cleaning the structs
	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Set the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	SiEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

	// This will fail but will return the PROC_THREAD_ATTRIBUTE_LIST size
	InitializeProcThreadAttributeList(NULL, 2, NULL, &sAttrSize);
	pAttrBuf = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sAttrSize);

	// Initialise the list with 2 attributes (one for block dll and one for ppid spoof)
	if (!InitializeProcThreadAttributeList(pAttrBuf, 2, NULL, &sAttrSize)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Atribute 1: BLOCK NON-MS DLLS ----------------------------------------------------------------------------------------------
	DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

	// Assigning the mitigation policy to the attribute list
	if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Atribute 2: PPID SPOOFING --------------------------------------------------------------------------------------------------
	if (!UpdateProcThreadAttribute(pAttrBuf, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Assigning the attributes to the STARTUPINFOEX
	SiEx.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pAttrBuf;


	if (!CreateProcessA(
		lpProcessName,
		COMMANDLINE,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		WORKINGDIRECTORY,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	// cleaning up
	DeleteProcThreadAttributeList(pAttrBuf);

	// Populate the OUTPUT parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	return TRUE;
}

int main()
{
	HANDLE hProcess = NULL, hThread = NULL;
	DWORD dwProcessId = NULL;
	HANDLE hPProcess = NULL;
	DWORD dwParentPID = 0;

	// Get the PID of the process to spoof
	dwParentPID = getPPID(PARENTPROCESS);
	// Check if dwParentPID is 0, then the target process is not running
	if (dwParentPID == 0) {
		printf("[!] Target process is not running \n");
		return -1;
	}

	// Openning a handle to the parent process
	if ((hPProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwParentPID)) == NULL) {
		printf("[!] OpenProcess Failed with Error : %d \n", GetLastError());
		return -1;
	}

	printf("[i] Spawning process \"%s\" in suspended state\n", SPAWNPROCESS);
	printf("[i] Setting up to block non-Microsoft DLLs to inject in the process\n");
	if (!SpawnProcess(hPProcess, SPAWNPROCESS, &dwProcessId, &hProcess, &hThread)) {
		return -1;
	}
	printf("[i] Target process spawned with PID %d \n", dwProcessId);

	printf("[i] Spoofing %ws (PID: %u) as the parent process.\n", PARENTPROCESS, dwParentPID);
	printf("\n[i] Press ENTER to resume the thread\n");
	getchar();

	// Resuming the process thread
	ResumeThread(hThread);

	// Closing handles
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}