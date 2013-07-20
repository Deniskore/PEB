#include "PEB.h"


PEBUtils::PEBUtils()
{
	hModule = NULL;
	procHandle = NULL;
	hProcess = NULL;
	pid = NULL;
	NtQueryInformationProcess = NULL;
	fIsWow64Process = NULL;
	AdjustPrivelege(SE_DEBUG_NAME);
	Init();
	memset(&peb32, 0, sizeof(peb32));
	memset(&peb64, 0, sizeof(peb64));
	memset(&pbi, 0, sizeof(pbi));

}

PEBUtils::~PEBUtils()
{
	FreeLibrary(hModule);
}

void PEBUtils::Init()
{
	HANDLE curProc = GetCurrentProcess();
	if(CheckProcess(curProc))
	{
		printf("Wow64 present..\n");
	}
	hModule = GetModuleHandleA("ntdll.dll");
    if(hModule == NULL)
    {
               printf("GetModuleHandle Error\n");
               exit(EXIT_FAILURE);
    }
    
    NtQueryInformationProcess = (lpfNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");

    if(NtQueryInformationProcess == NULL)
    {
        printf("GetProcAddress Error\n");
		exit(EXIT_FAILURE);
    }

}


void PEBUtils::AdjustPrivelege(LPWSTR privelege)
{
   HANDLE hToken = NULL;
   TOKEN_PRIVILEGES tokenPriv;
   LUID luidDebug;
   if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken) != FALSE) 
   {
      if(LookupPrivilegeValue(NULL, privelege, &luidDebug) != FALSE)
      {
         tokenPriv.PrivilegeCount           = 1;
         tokenPriv.Privileges[0].Luid       = luidDebug;
         tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
         if(AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, 0, NULL, NULL) != FALSE)
         {
            printf("CHANGED TOKEN PRIVILEGES\n");
         }
         else
         {
            printf("FAILED TO CHANGE TOKEN PRIVILEGES\n");
			exit(EXIT_FAILURE);
         }
      }
   }
   CloseHandle(hToken);

}

HANDLE PEBUtils::OpenProcess(LPWSTR &procName)
{
	PROCESSENTRY32   pe32;
	HANDLE           hSnapshot = NULL;

	pe32.dwSize = sizeof( PROCESSENTRY32 );
	hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

	if( Process32First( hSnapshot, &pe32 ) )
	{
		do{
			if( lstrcmpiW( pe32.szExeFile, procName) == 0 )
			{
				pid = pe32.th32ProcessID;
				break;
			}
		}while( Process32Next( hSnapshot, &pe32 ) );
	}

	if( hSnapshot != INVALID_HANDLE_VALUE )
		CloseHandle( hSnapshot );

	procHandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
	if (procHandle == INVALID_HANDLE_VALUE)
	{
		printf("OpenProcess Error\n ", procName);
		exit(EXIT_FAILURE);
	}
	else
		return procHandle;
}

HANDLE PEBUtils::OpenProcess(DWORD pid)
{
	return ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

void PEBUtils::ReadPEB(SIZE_T &dwBytesRead)
{
	SuspendThread(hProcess);
    if(!ReadProcessMemory(hProcess, (void*)pbi.PebBaseAddress, &peb32, sizeof(PEB32), &dwBytesRead) || dwBytesRead < sizeof(PEB32))
	{
	   printf("ReadProcessMemory Error 0x%x", GetLastError());
	   exit(EXIT_FAILURE);
	}	
	ResumeThread(hProcess);
}

void PEBUtils::ReadPEB64(SIZE_T &dwBytesRead)
{
	SuspendThread(hProcess);
    if(!ReadProcessMemory(hProcess, (void*)pbi.PebBaseAddress, &peb64, sizeof(PEB64), &dwBytesRead) || dwBytesRead < sizeof(PEB64))
	{
	   printf("ReadProcessMemory Error 0x%x", GetLastError());
	   exit(EXIT_FAILURE);
	}	
	ResumeThread(hProcess);
}

PEB32 PEBUtils::GetProcessPEB32(LPWSTR &procName)
{        
	hProcess = OpenProcess(procName);
	if(!CheckProcess(hProcess))
	{
		printf("Remote Process is 64 bit but using GetProcesPeb32\n");
		exit(EXIT_FAILURE);
	}
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);
    
    if(status != 0x0)
    {
        printf("NtQueryInformationProcess Error  0x%x\n", status);
		exit(EXIT_FAILURE);
    }
    
    printf("PEB address : 0x%x\n", pbi.PebBaseAddress);

	SIZE_T dwBytesRead = 0x0;
	/*SIZE_T oldP = 0;
	MEMORY_BASIC_INFORMATION mb;
	VirtualQueryEx(hProcess,(void*)pbi.PebBaseAddress,&mb,sizeof(mb));
	if(!VirtualProtectEx(hProcess, (void*)pbi.PebBaseAddress, mb.RegionSize, PAGE_READONLY, &oldP))
	{
	   printf("VirtualProtect Error 0x%x", GetLastError());
	   exit(EXIT_FAILURE);
	}*/
	ReadPEB(dwBytesRead);

    return peb32;
}

PEB64 PEBUtils::GetProcessPEB64(LPWSTR &procName)
{    
	hProcess = OpenProcess(procName);
	if(CheckProcess(hProcess))
	{
		printf("Remote Process is 32 bit but using GetProcesPeb64\n");
		exit(EXIT_FAILURE);
	}
    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &dwLength);
    
    if(status != 0x0)
    {
        printf("NtQueryInformationProcess Error  0x%x\n", status);
		exit(EXIT_FAILURE);
    }
    
    printf("PEB address : 0x%x\n", pbi.PebBaseAddress);

    SIZE_T dwBytesRead = 0x0;
	ReadPEB64(dwBytesRead);

    return peb64;
}

BOOL PEBUtils::CheckProcess(HANDLE &hProcess)
{
	BOOL bIsWow64 = FALSE;

	fIsWow64Process = (lpfIsWow64Process) GetProcAddress(
        GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

    if(NULL != fIsWow64Process)
    {
        if (!fIsWow64Process(hProcess,&bIsWow64))
        {
			printf("ERROR with IsWow64Process 0x%x", GetLastError());
			exit(EXIT_FAILURE);
        }
    }
	return bIsWow64;
}

void PEBUtils::SetProcessPEB32(LPWSTR &procName, PEB32 &peb32)
{
	hProcess = OpenProcess(procName);

	SIZE_T dwBytesWritten = 0x0;
	DWORD oldP = 0;
	MEMORY_BASIC_INFORMATION mb;
	SuspendThread(hProcess);
	VirtualQueryEx(hProcess, (void*)pbi.PebBaseAddress,&mb,sizeof(mb));
	if(!VirtualProtectEx(hProcess, (void*)pbi.PebBaseAddress, mb.RegionSize, PAGE_READWRITE, &oldP))
	{
	   printf("VirtualProtect Error 0x%x", GetLastError());
	   exit(EXIT_FAILURE);
	}
	WriteProcessMemory(hProcess, (void*)pbi.PebBaseAddress, &peb32, sizeof(PEB32), &dwBytesWritten);
	ResumeThread(hProcess);
}

void PEBUtils::SetProcessPEB64(LPWSTR &procName, PEB64 &peb64)
{
	hProcess = OpenProcess(procName);
	SIZE_T dwBytesWritten = 0x0;
	DWORD oldP = 0;
	MEMORY_BASIC_INFORMATION mb;
	SuspendThread(hProcess);
	VirtualQueryEx(hProcess,(void*)pbi.PebBaseAddress,&mb,sizeof(mb));
	if(!VirtualProtectEx(hProcess, (void*)pbi.PebBaseAddress, mb.RegionSize, PAGE_READWRITE, &oldP))
	{
	   printf("VirtualProtect Error 0x%x", GetLastError());
	   exit(EXIT_FAILURE);
	}
	WriteProcessMemory(hProcess, (void*)pbi.PebBaseAddress, &peb64, sizeof(PEB64), &dwBytesWritten);
	ResumeThread(hProcess);

}