#include <iostream>
#include "Load.h"

// "Load.h"来自于 看雪，修改于"MemoryLoadDll"
// "Main.cpp"由本人所写，切勿用于非法商业用途
//					2019.01.6	By:Kanren

DWORD GetShellCodeSize()
{
	DWORD size = 0;
	WORD* Memx = (WORD*)MemLoadLibrary2;
	while (*Memx != 0xCCCC)
	{
		Memx++;
		size += 2;
	}
	return size;
}

void main()
{
	HANDLE ProcessHandle;
	DWORD ProcessId = 0, DataLength = 0, ShellCodeSize = GetShellCodeSize();
	std::cout << "Current Process Id:" << GetCurrentProcessId() << std::endl;
	std::cout << "Target Process Id:";
	std::cin >> ProcessId;
	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
	if (ProcessHandle)
	{
		std::cout << "Process Handle:" << ProcessHandle << std::endl;
		HANDLE Dll = CreateFile("Test.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		if (Dll != INVALID_HANDLE_VALUE)
		{
			std::cout << "File Handle:" << Dll << std::endl;
			DWORD FileSize = GetFileSize(Dll, NULL);
			if (FileSize > 0)
			{
				std::cout << "File Size:" << FileSize << std::endl;
				PVOID FileBuffer = malloc(FileSize);
				ZeroMemory(FileBuffer, FileSize);
				std::cout << "File Memory:" << FileBuffer << std::endl;
				if (ReadFile(Dll, FileBuffer, FileSize, &DataLength, NULL))
				{
					DWORD AllocMemorySize = FileSize + ShellCodeSize + sizeof(PARAMX) + 0x100;
					PVOID ShellCodeAddr = VirtualAllocEx(ProcessHandle, NULL, AllocMemorySize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					std::cout << "Alloc Memory Size:" << AllocMemorySize << std::endl;
					std::cout << "ShellCode Addr:" << ShellCodeAddr << std::endl;
					if (ShellCodeAddr)
					{
						PARAMX List;
						List.DataLength = FileSize;
						List.lpFileData = ShellCodeAddr;
						HMODULE NtDll = GetModuleHandleA("ntdll.dll");
						List.pLdrLoadDll = (LdrLoadDllT)GetProcAddress(NtDll, "LdrLoadDll");
						List.RtlInitAnsiString = (RtlInitAnsiStringT)GetProcAddress(NtDll, "RtlInitAnsiString");
						List.RtlFreeUnicodeString = (RtlFreeUnicodeStringT)GetProcAddress(NtDll, "RtlFreeUnicodeString");
						List.LdrGetProcedureAddress = (LdrGetProcedureAddressT)GetProcAddress(NtDll, "LdrGetProcedureAddress");;
						List.dwNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)GetProcAddress(NtDll, "NtAllocateVirtualMemory");
						List.RtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)GetProcAddress(NtDll, "RtlAnsiStringToUnicodeString");
						std::cout << "Ntdll Handle:" << NtDll << std::endl;
						std::cout << "LdrLoadDll:" << List.pLdrLoadDll << std::endl;
						std::cout << "RtlInitAnsiString:" << List.RtlInitAnsiString << std::endl;
						std::cout << "RtlFreeUnicodeString:" << List.RtlFreeUnicodeString << std::endl;
						std::cout << "LdrGetProcedureAddress:" << List.LdrGetProcedureAddress << std::endl;
						std::cout << "NtAllocateVirtualMemory:" << List.dwNtAllocateVirtualMemory << std::endl;
						std::cout << "RtlAnsiStringToUnicodeString:" << List.RtlAnsiStringToUnicodeString << std::endl;
						if (ShellCodeSize > 0)
						{
							WriteProcessMemory(ProcessHandle, ShellCodeAddr, FileBuffer, FileSize, (SIZE_T*)&DataLength);
							WriteProcessMemory(ProcessHandle, (PVOID)((ULONG64)ShellCodeAddr + FileSize), MemLoadLibrary2, ShellCodeSize, (SIZE_T*)&DataLength);
							WriteProcessMemory(ProcessHandle, (PVOID)((ULONG64)ShellCodeAddr + FileSize + ShellCodeSize), &List, sizeof(List), (SIZE_T*)&DataLength);
							std::cout << "StartAddress:" << (LPTHREAD_START_ROUTINE)((ULONG64)ShellCodeAddr + FileSize) << std::endl;
							std::cout << "Parameter:" << (PVOID)((ULONG64)ShellCodeAddr + FileSize + ShellCodeSize) << std::endl;
							HANDLE Thread = CreateRemoteThreadEx(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)((ULONG64)ShellCodeAddr + FileSize), (PVOID)((ULONG64)ShellCodeAddr + FileSize + ShellCodeSize), 0, NULL, NULL);
							if (Thread > 0)
							{
								CloseHandle(Thread);
							}
							else
								std::cout << "Create Remote Thread Zero" << std::endl;
							VirtualFreeEx(ProcessHandle, ShellCodeAddr, AllocMemorySize, MEM_RELEASE);
							CloseHandle(Dll);
							CloseHandle(ProcessHandle);
						}
						else
							std::cout << "ShellCode Size Is Zero" << std::endl;
					}
					else
						std::cout << "Alloc Virtual Memory Error" << std::endl;
				}
				else
					std::cout << "Read File Error" << std::endl;
			}
			else
				std::cout << "File Size Is Zero" << std::endl;
		}
		else
			std::cout << "Open File Error" << std::endl;
	}
	else
		std::cout << "Open Process Error" << std::endl;
	system("pause");
}