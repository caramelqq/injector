#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#define PROCESS_NAME "winmine.exe"
#define DLL_NAME "simpledll.dll"
//#define DLL_NAME "C:\\Users\\David\\Desktop\\simpledll.dll"

//I could just use PROCESS_ALL_ACCESS but it's always best to use the absolute bare minimum of priveleges, so that your code works in as
//many circumstances as possible.
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
 
BOOL WriteProcessBYTES(HANDLE hProcess,LPVOID lpBaseAddress,LPCVOID lpBuffer,SIZE_T nSize);

BOOL LoadDll(char *procName, char *dllName);
BOOL InjectDLL(DWORD ProcessID,char *dllName);
int getpidfromname(char *ProcName);

bool IsWindowsNT()
{
	/*
   // check current version of Windows
   DWORD version = GetVersion();
   // parse return
   DWORD majorVersion = (DWORD)(LOBYTE(LOWORD(version)));
   DWORD minorVersion = (DWORD)(HIBYTE(LOWORD(version)));
   return (version < 0x80000000);
   */
	return true;
}

int WINAPI WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPSTR lpCmdLine,int nCmdShow)
{
    if(IsWindowsNT())
       LoadDll(PROCESS_NAME, DLL_NAME);
    else
   MessageBox(0, L"Your system does not support this method", L"Error!", 0);

    return 0;
}

int getpidfromname(char *ProcName)
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	//take snapshot of processes
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//set size of pe32 size
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//loop through all process names
	wchar_t unicodesucks[50];
	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, ProcName, -1, unicodesucks, sizeof(wchar_t)*50);
	
	if(Process32First( hProcessSnap, &pe32))
	{
		while(Process32Next(hProcessSnap, &pe32))
		{
			if(wcscmp(pe32.szExeFile, unicodesucks) == 0 )
				return pe32.th32ProcessID;
		}
	}

	return NULL;
}
BOOL LoadDll(char *procName, char *dllName)
{
   DWORD ProcID = 0;

   ProcID = getpidfromname(procName);

   if(InjectDLL(ProcID, dllName))
      return true;
   
   return false;
}

BOOL InjectDLL(DWORD ProcessID, char *dllName)
{
	HANDLE Proc;
	LPVOID RemoteString, LoadLibAddy;

	if(!ProcessID)
	{
		MessageBox(NULL, L"Cannot Find PID", L"Loader", NULL);
		return false;
	}
	Proc = OpenProcess(CREATE_THREAD_ACCESS, FALSE, ProcessID);

	if(!Proc)
	{
		//swprintf(buf, L"OpenProcess() failed: %d", GetLastError());
		MessageBox(NULL, L"Cannot open process", L"Loader", NULL);
		return false;
	}

	//get address of LoadLibraryA in kernel32.dll
	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	//allocate memory for name of dll to be executed in target
	RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(dllName), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

	//write name of dll to be executed to  - dllName must be ansi
	WriteProcessMemory(Proc, (LPVOID)RemoteString, dllName, strlen(dllName), NULL);

	//start remote thread
	if(CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL))   
		MessageBox(NULL, L"Injected", L"Injected", MB_OK);

	CloseHandle(Proc);
	
	return true;
}
