#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "importless.h"

static enum importless_error error_code;
enum importless_error importless_get_error(void) {
	return error_code;
}

static PEB* get_peb(void) {
#if defined(_M_X64)
	uint64_t offset = (uint64_t)&((NT_TIB*)NULL)->Self;
	TEB* thread_environment_block = (TEB*)__readgsqword(offset);
#else
	uint32_t offset = (uint32_t)&((NT_TIB*)NULL)->Self;
	TEB* thread_environment_block = (TEB*)__readfsdword(offset);
#endif
	return thread_environment_block->ProcessEnvironmentBlock;
}

static PEB* peb = NULL;
void* importless_get(const char* module_name, const char* proc_name) {
	peb = get_peb();
	if (!peb) {
		error_code = importless_peb_error;
		return NULL;
	}

	HINSTANCE found_module = NULL;

	// Locate module:
	LDR_DATA_TABLE_ENTRY* first = CONTAINING_RECORD((PLIST_ENTRY)peb->Ldr->InMemoryOrderModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	LDR_DATA_TABLE_ENTRY* current = first;
	do {
		// Path conversions be like:
		// I actually could've done this in a single import but I want to avoid imports lmao.
		char ansi_path[MAX_PATH];
		wcstombs_s(NULL, ansi_path, current->FullDllName.Buffer, current->FullDllName.MaximumLength);
		char ansi_name[MAX_PATH];
		char ansi_ext[MAX_PATH];
		_splitpath_s(ansi_path, NULL, 0, NULL, 0, ansi_name, MAX_PATH, ansi_ext, MAX_PATH);
		strcat_s(ansi_name, ansi_ext);

		if (!_strnicmp(ansi_name, module_name, MAX_PATH)) {
			found_module = (HINSTANCE)current->DllBase;
			break;
		}

		current = (LDR_DATA_TABLE_ENTRY*)(((struct _LIST_ENTRY*)current)->Flink);
	} while (first != current);
	if (!found_module) {
		error_code = importless_module_not_found;
		return NULL;
	}

	IMAGE_DOS_HEADER* dos_hdr = (IMAGE_DOS_HEADER*)found_module;
	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE) {
		error_code = importless_module_not_found;
		return NULL;
	}
	IMAGE_NT_HEADERS* nt_hdr = (IMAGE_NT_HEADERS*)((char*)dos_hdr + dos_hdr->e_lfanew);
	if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
		error_code = importless_module_not_found;
		return NULL;
	}
	if (!nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
		error_code = importless_module_not_found;
		return NULL;
	}
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)dos_hdr + nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 
	uint32_t* names = (uint32_t*)((char*)dos_hdr + exports->AddressOfNames);
	uint16_t* ordinals = (uint16_t*)((char*)dos_hdr + exports->AddressOfNameOrdinals);
	uint32_t* functions = (uint32_t*)((char*)dos_hdr + exports->AddressOfFunctions);
	for (int i = 0; i < exports->NumberOfNames; i++) {
		char* name = (char*)dos_hdr + names[i];
		if (!strncmp(name, proc_name, strlen(name))) {
			uint32_t ord = ordinals[i];
			uint32_t ptr = functions[ord];
			error_code = importless_ok;
			return (char*)dos_hdr + ptr;
		}
	}
	
	error_code = importless_proc_not_found;
	return NULL;
}