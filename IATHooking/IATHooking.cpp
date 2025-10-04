// IAT Hooking, Barak Gonen Aug 2020

#include "pch.h"

#define MAX 100
#define FILENAME "C:\\Users\\IMOE001\\source\\repos\\IATHooking\\pch.h"
//#define FILENAME "pch.h"

int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_address);
void ShowMsg();
DWORD saved_hooked_func_addr;

void PrintLastErrorMessage(DWORD errorCode) {
	char* messageBuffer = NULL;

	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		0, // Default language
		(LPSTR)&messageBuffer,
		0,
		NULL
	);

	if (messageBuffer) {
		printf("Error %lu: %s\n", errorCode, messageBuffer);
		LocalFree(messageBuffer);
	}
	else {
		printf("Error %lu: (Unable to retrieve message)\n", errorCode);
	}
}

int main()
{
	PCSTR func_to_hook = "CreateFileA";
	PCSTR DLL_to_hook = "KERNEL32.dll";
	DWORD new_func_address = (DWORD)&ShowMsg;
	HANDLE hFile;
	hook(func_to_hook, DLL_to_hook, new_func_address);
	// open the file for reading
	char cwd[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, cwd);
	printf("Current Working Directory: %s\n", cwd);

	hFile = CreateFileA(FILENAME,   // file name
		GENERIC_READ,           // open for read
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,          // open only if exists
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template


	// if file was not opened, print error code and return
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		//printf("Error code: %d\n", error);
		PrintLastErrorMessage(error);
		return 0;
	}

	// read some bytes and print them
	CHAR buffer[MAX];
	DWORD num;
	LPDWORD numread = &num;
	BOOL result = ReadFile(hFile,   // handle to open file
		buffer,						// pointer to buffer to store data
		MAX - 1,					// bytes to read
		numread,					// return value - bytes actually read
		NULL);						// overlapped
	buffer[*numread] = 0;
	printf("%s\n", buffer);

	// close file
	CloseHandle(hFile);
	return 0;
};

int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD new_func_address) {
	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS NTHeader;
	PIMAGE_OPTIONAL_HEADER32 optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD descriptorStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
	int index;

	// Get base address of currently running .exe
	DWORD baseAddress = (DWORD)GetModuleHandle(NULL);

	// Get the import directory address
	dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);

	if (((*dosHeader).e_magic) != IMAGE_DOS_SIGNATURE) {
		return 0;
	}

	// Locate NT header
	NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + (*dosHeader).e_lfanew);
	if (((*NTHeader).Signature) != IMAGE_NT_SIGNATURE) {
		return 0;
	}

	// Locate optional header
	optionalHeader = &(*NTHeader).OptionalHeader ;
	if (((*optionalHeader).Magic) != 0x10B) {
		return 0;
	}

	importDirectory = (*optionalHeader).DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	descriptorStartRVA = importDirectory.VirtualAddress ;
	importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress +descriptorStartRVA);
	
	index = 0;
	char* DLL_name;
	// Look for the DLL which includes the function for hooking
	while (importDescriptor[index].Characteristics != 0) {
		DLL_name = (char*)(baseAddress + importDescriptor[index].Name);
		printf("DLL name: %s\n", DLL_name);
		if (!strcmp(DLL_to_hook, DLL_name))
			break;
		index++;
	}

	// exit if the DLL is not found in import directory
	if (importDescriptor[index].Name == 0) {
		printf("DLL was not found");
		return 0;
	}

	// Search for requested function in the DLL
	PIMAGE_THUNK_DATA thunkILT; // Import Lookup Table - names
	PIMAGE_THUNK_DATA thunkIAT; // Import Address Table - addresses
	PIMAGE_IMPORT_BY_NAME nameData;

	thunkILT = (PIMAGE_THUNK_DATA)(baseAddress +importDescriptor[index].Characteristics);
	thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress +importDescriptor[index].FirstThunk);
	if ((thunkIAT == NULL) or (thunkILT == NULL)) {
		return 0;
	}

	while (((*thunkILT).u1.AddressOfData != 0) & (!((*thunkILT).u1.Ordinal & IMAGE_ORDINAL_FLAG))) {
		nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + (*thunkILT).u1.AddressOfData);
		if (!strcmp(func_to_hook, (char*)(*nameData).Name))
			break;
		thunkIAT++;
		thunkILT++;
	}

	printf("CreateFileA pointer is : %p\n", (*thunkIAT).u1.Function);
	// Hook IAT: Write over function pointer
	DWORD dwOld = NULL;
	saved_hooked_func_addr = (*thunkIAT).u1.Function;
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld);
	(*thunkIAT).u1.Function = new_func_address;
	VirtualProtect((LPVOID) & ((*thunkIAT).u1.Function), sizeof(DWORD), dwOld, NULL);

	return 1;
};

void ShowMsg() {
	MessageBoxA(0, "Hooked", "I Love Assembly", 0);

	_asm {
		pop edi
		pop esi
		pop ebx
		add esp, 0C0h; Release local stack(match sub esp, 0C0h)
		mov esp, ebp
		pop ebp
		jmp saved_hooked_func_addr
	}
}
