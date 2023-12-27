#pragma once

#define SYSCALL_CODE 0xDFEB33F

enum operation : int
{
	memory_read = 0,
	memory_write,
	module_base,
	mget_cr3,
	mget_pe,
	mget_gaurded,
};

struct cmd_t
{
	bool success = false;
	unsigned int verification_code = 0;
	operation operation;
	UINT64 target_pid = 0;
	UINT64 target_address = 0x0;
	UINT64 buffer_address = 0x0;
	SIZE_T size = 0;
	SIZE_T return_size = 0;
	LPCWSTR ModuleName = 0;
	PVOID ModuleBase = 0;
	PVOID Entrypoint = 0;
	PVOID PEB = 0;
	PVOID ModuleSize = 0;
	uintptr_t allocation;
	long x;
	long y;
	unsigned short button_flags;
};