#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define SystemHandleInformation 0x10
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define INITIAL_SYSTEM_HANDLE_INFORMATION_SIZE 1024 * 1024
#define FileNameInformation 9


using namespace std;
using NtQuerySystemInformationPTR = DWORD(WINAPI*)(DWORD SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
using NtQueryInformationFilePTR = DWORD(WINAPI*)(HANDLE FileHandle, void* IoStatusBlock, PVOID FileInformation, ULONG Length, DWORD FileInformationClass);
using NtSuspendProcessPTR = DWORD(WINAPI*)(HANDLE Process);
using NtResumeProcessPTR = DWORD(WINAPI*)(HANDLE Process);


////////////////////////////////////////////////////////////
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



struct FILE_NAME_INFORMATION
{
	ULONG FileNameLength;
	WCHAR FileName[1];
};

struct IO_STATUS_BLOCK
{
	union
	{
		DWORD Status;
		PVOID Pointer;
	};
	DWORD* Information;
};

struct GetFileHandlePathThreadParamStruct
{
	HANDLE hFile;
	char szPath[512];
};


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


/////////////////////////////////////////////////////
NtQuerySystemInformationPTR NtQuerySystemInformation = (NtQuerySystemInformationPTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
NtQueryInformationFilePTR NtQueryInformationFile = (NtQueryInformationFilePTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationFile");
NtSuspendProcessPTR NtSuspendProcess = (NtSuspendProcessPTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
NtResumeProcessPTR NtResumeProcess = (NtResumeProcessPTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtResumeProcess");


int main() {

	DWORD PID = 12356;
	HANDLE hprocess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_SUSPEND_RESUME, FALSE, PID);
	PVOID bFileInfoBuffer;
	IO_STATUS_BLOCK IoStatusBlock;
	SecureZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	ULONG bufferSize = sizeof(FILE_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR);
	bFileInfoBuffer = malloc(bufferSize);
	ZeroMemory(bFileInfoBuffer, bufferSize);



	HANDLE cloneHandle = NULL;
	HANDLE hExistingRemoteHandle = NULL;
	ULONG returnLength = 0;
	ULONG systemHandleInformationSize = INITIAL_SYSTEM_HANDLE_INFORMATION_SIZE;
	NTSTATUS status;
	NtQuerySystemInformationPTR NtQuerySystemInformation = (NtQuerySystemInformationPTR)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	PSYSTEM_HANDLE_INFORMATION handleTableInformation = nullptr;

	do {
		handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, systemHandleInformationSize);
		if (!handleTableInformation) {
			std::cerr << "HeapAlloc failed" << std::endl;
			return 1;
		}

		status = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, systemHandleInformationSize, &returnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			HeapFree(GetProcessHeap(), 0, handleTableInformation);
			systemHandleInformationSize *= 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = handleTableInformation->Handles[i];
		if (handleInfo.UniqueProcessId == PID) {
			//printf_s("Handle 0x%x at 0x%p, PID: (%d)  -> %d\n", handleInfo.HandleValue, handleInfo.Object, handleInfo.UniqueProcessId, handleInfo.ObjectTypeIndex);
			if (handleInfo.ObjectTypeIndex == 40) {
				std::cout << "it is file:  0x" << std::hex << handleInfo.HandleValue << std::endl;

				DuplicateHandle(hprocess, (HANDLE)handleInfo.HandleValue, GetCurrentProcess(), &cloneHandle, 0, 0, DUPLICATE_SAME_ACCESS);

				NtQueryInformationFile(cloneHandle, &IoStatusBlock, bFileInfoBuffer, bufferSize, FileNameInformation);
				FILE_NAME_INFORMATION* fileNameInfo = (FILE_NAME_INFORMATION*)bFileInfoBuffer;
				std::wcout << L"File path: " << std::wstring(fileNameInfo->FileName, fileNameInfo->FileNameLength / sizeof(WCHAR)) << std::endl;
			}
		}
	}

	getchar();
	return 0;
}
