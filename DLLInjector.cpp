#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>
using namespace std;

string translateString(char* name);
HANDLE getHandleToTargetProcess(const string& targetName);

int main()
{
	string targetName;
	string path;

	cout << "Enter the name of the process we are injecting into.\n";
	cin >> targetName;
	cout << "Enter the path to the dll.\n";
	cin >> path;

	
	char* dllPath = new char[path.size() + 1];
	for (int i = 0; i < path.size(); i++)
	{
		dllPath[i] = path[i];
	}
	dllPath[path.size()] = '\0';

	// First we need to grab a handle to the target process
	HANDLE target = getHandleToTargetProcess(targetName);
	if (target == NULL)
	{
		cout << "Injection Failed. error: 1\n";
		cin.ignore();
		cin.get();
		return -1;
	}

	// Allocate memory inside of target process to store path name of dll
	LPVOID addressOfAllocatedMemory = VirtualAllocEx(target, NULL, path.size(), MEM_COMMIT, PAGE_READWRITE);
	if (addressOfAllocatedMemory == NULL)
	{
		cout << "Injection Failed. error: 2\n";
		cin.ignore();
		cin.get();
		return -1;
	}

	// Now write our dll's path into our allocated memory
	WriteProcessMemory(target, addressOfAllocatedMemory, dllPath, path.size(), 0);

	/*
	* Get address of the LoadLibrary function.
	*/
	LPVOID addr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (addr == NULL) {
		printf("Error: the LoadLibraryA function was not found inside kernel32.dll library.\n");
		cin.ignore();
		cin.get();
		return -1;
	}

	// Create a remote thread in our target that calls load library
	HANDLE loaderThread = CreateRemoteThread(target, NULL, 0, (LPTHREAD_START_ROUTINE)addr, addressOfAllocatedMemory, NULL, NULL);
	if (loaderThread == NULL)
	{
		cout << "Injection Failed. error: 3\n";
		cin.ignore();
		cin.get();
		return -1;
	}

	// Wait for loader thread to finish executing
	WaitForSingleObject(loaderThread, INFINITE);

	// Free our memory
	VirtualFreeEx(target, dllPath, path.size(), MEM_RELEASE);

	cout << "Memory injected successfully at: " << addressOfAllocatedMemory << endl;
	cout << "Press Enter to close...";
	cin.ignore();
	cin.get();

	return 0;
}

string translateString(char* name)
{
	string foundModuleName;
	int count = 0;
	char c = name[count];
	while (c != '\0')
	{
		foundModuleName += c;
		count++;
		c = name[count];
	}

	return foundModuleName;
}

HANDLE getHandleToTargetProcess(const string& targetName)
{
	HANDLE solution = NULL;
	HANDLE targetSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (targetSnapshot == INVALID_HANDLE_VALUE)
		return false;

	PROCESSENTRY32 processData;
	processData.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(targetSnapshot, &processData))
	{
		string foundProcessName = translateString((char*)processData.szExeFile);
		//std::cout << foundProcessName << std::endl;
		//cin.get();

		if (foundProcessName == targetName)
		{
			solution = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processData.th32ProcessID);
			return solution;
		}
		else
		{
			while (Process32Next(targetSnapshot, &processData))
			{
				string foundProcessName = translateString((char*)processData.szExeFile);
				//std::cout << foundProcessName << std::endl;
				//cin.get();

				if (foundProcessName == targetName)
				{
					solution = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processData.th32ProcessID);
					return solution;
				}
			}
		}
	}

	return solution;
}
