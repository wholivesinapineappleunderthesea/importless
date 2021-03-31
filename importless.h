#ifndef IMPORTLESS_HEADER_GUARD
#define IMPORTLESS_HEADER_GUARD

// Error codes:
enum importless_error {
	importless_ok,
	importless_peb_error,
	importless_module_not_found,
	importless_proc_not_found
};

void* importless_get(const char* module_name, const char* proc_name);
enum importless_error importless_get_error(void);

#endif