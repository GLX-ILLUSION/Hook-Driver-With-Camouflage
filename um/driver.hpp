#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include "communication.hpp"

namespace offsets
{
	DWORD
		uworldptr = 0x60,
		ulevel = 0x38,
		gamestate = 0x140;

}
namespace driver
{
	uintptr_t _guardedregion;
	int process_id;

	__int64(__fastcall* NtUserSetGestureConfig)(void* a1) = nullptr;

	bool setup()
	{
		LoadLibraryA("user32.dll");
		LoadLibraryA("win32u.dll");

		const HMODULE win32u = GetModuleHandleA("win32u.dll");
		if (!win32u)
			return false;

		*(void**)&NtUserSetGestureConfig = GetProcAddress(win32u, "NtUserSetGestureConfig");

		return NtUserSetGestureConfig;
	}

	bool send_cmd(cmd_t* cmd)
	{
		RtlSecureZeroMemory(cmd, 0);
		NtUserSetGestureConfig(cmd);
		return cmd->success;
	}

	int get_process_id(const char* process_name)
	{
		PROCESSENTRY32 proc_info;
		proc_info.dwSize = sizeof(proc_info);

		const auto proc_snapshot =
			CreateToolhelp32Snapshot(
				TH32CS_SNAPPROCESS,
				NULL
			);

		if (proc_snapshot == INVALID_HANDLE_VALUE)
			return NULL;

		Process32First(proc_snapshot, &proc_info);
		if (!strcmp(proc_info.szExeFile, process_name)) {
			CloseHandle(proc_snapshot);
			return proc_info.th32ProcessID;
		}

		while (Process32Next(proc_snapshot, &proc_info)) {
			if (!strcmp(proc_info.szExeFile, process_name)) {
				CloseHandle(proc_snapshot);
				return proc_info.th32ProcessID;
			}
		}

		CloseHandle(proc_snapshot);
		return {};
	}

	PVOID get_module_base(LPCWSTR ModuleToSearch)
	{
		cmd_t cmd{};

		cmd.verification_code = SYSCALL_CODE;
		cmd.target_pid  = process_id;
		cmd.operation = module_base;
		cmd.ModuleName = ModuleToSearch;

		send_cmd(&cmd);

		return cmd.ModuleBase;
	}
	PVOID get_module_size(LPCWSTR ModuleToSearch)
	{
		cmd_t cmd{};

		cmd.verification_code = SYSCALL_CODE;
		cmd.target_pid = process_id;
		cmd.operation = module_base;
		cmd.ModuleName = ModuleToSearch;

		send_cmd(&cmd);

		return cmd.ModuleSize;
	}
    
	PVOID get_cr3()
	{
		cmd_t cmd{};
		cmd.target_pid = driver::get_process_id("RustClient.exe");
		cmd.operation = mget_cr3;
		send_cmd(&cmd);
	}

	template<typename T> T ReadMemory(const UINT64 address) 
	{
		cmd_t cmd{};
		T buffer;
		cmd.verification_code = SYSCALL_CODE;
		cmd.operation = memory_read;
		cmd.target_pid = process_id;
		cmd.buffer_address = (UINT64)& buffer;
		cmd.target_address = address;
		cmd.size = sizeof(T);
		send_cmd(&cmd);
		return cmd.buffer_address;
	}

	template<typename T> bool WriteMemory(const UINT64 address, const T buffer) {

		cmd_t cmd{};
		cmd.verification_code = SYSCALL_CODE;
		cmd.operation = memory_write;
		cmd.target_pid = process_id;
		cmd.target_address = address;
		cmd.buffer_address = &buffer;
		cmd.size = sizeof(T);
		send_cmd(&cmd);
	}
	void* PatternScan(char* base, size_t size, const char* pattern, const char* mask)
	{
		size_t patternLength = strlen(mask);

		for (unsigned int i = 0; i < size - patternLength; i++)
		{
			bool found = true;
			for (unsigned int j = 0; j < patternLength; j++)
			{
				if (mask[j] != '?' && pattern[j] != *(base + i + j))
				{
					found = false;
					break;
				}
			}
			if (found)
			{
				return (void*)(base + i);
			}
		}
		return nullptr;
	}

	uintptr_t PatternScanEx(uintptr_t begin, uintptr_t end, const char* pattern, const char* mask)
	{
		uintptr_t currentChunk = begin;
		SIZE_T bytesRead;
		cmd_t cmd{};
		cmd.target_pid = process_id;
		while (currentChunk < end)
		{
			char buffer[4096];
			cmd.operation = memory_read;
			cmd.target_address = currentChunk;
			cmd.buffer_address = (UINT64)&buffer;
			cmd.size = sizeof(buffer);
			send_cmd(&cmd);
			bytesRead = cmd.return_size;
			if (bytesRead == 0)
			{
				return 0;
			}
			void* internalAddress = PatternScan((char*)&buffer, bytesRead, pattern, mask);
			if (internalAddress != nullptr)
			{
				//calculate from internal to external
				uintptr_t offsetFromBuffer = (uintptr_t)internalAddress - (uintptr_t)&buffer;
				return (uintptr_t)(currentChunk + offsetFromBuffer);
			}
			else
			{
				//advance to next chunk
				currentChunk = currentChunk + bytesRead;
			}
		}
		return 0;
	}

	auto guarded_region() -> uintptr_t
	{
		cmd_t cmd{};
		cmd.operation = mget_gaurded;
		_guardedregion = cmd.allocation;
		return cmd.allocation;
	}

	template<typename T> T readguarded(uintptr_t src, size_t size = sizeof(T))
	{
		T buffer;
		cmd_t cmd{};
		cmd.verification_code = SYSCALL_CODE;
		cmd.operation = memory_read;
		cmd.target_pid = process_id;
		cmd.target_address = src;
		cmd.buffer_address = (uintptr_t)&buffer;
		cmd.size = size;
		send_cmd(&cmd);
		uintptr_t val = _guardedregion + (*(uintptr_t*)&cmd.buffer_address & 0xFFFFFF);
		return *(T*)&val;
	}


	inline static bool isguarded(uintptr_t pointer)
	{
		static constexpr uintptr_t filter = 0xFFFFFFF000000000;
		uintptr_t result = pointer & filter;
		return result == 0x8000000000 || result == 0x10000000000;
	}

	template <typename T>
	T read(T src)
	{
		T buffer = ReadMemory<uintptr_t >(src);

		if (isguarded((uintptr_t)buffer))
		{
			return readguarded< uintptr_t >(src);
		}
		return buffer;
	}

	auto getuworld(uintptr_t pointer) -> uintptr_t
	{
		uintptr_t uworld_addr = read<uintptr_t>(pointer + offsets::uworldptr);
		unsigned long long uworld_offset;

		if (uworld_addr > 0x10000000000)
		{
			uworld_offset = uworld_addr - 0x10000000000;
		}
		else {
			uworld_offset = uworld_addr - 0x8000000000;
		}

		return pointer + uworld_offset;
	}

}