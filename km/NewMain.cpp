#include <ntifs.h>
#include "Utils.h"
#include "Crypter.h"
#include "VMP.h"
#include "SelfDestruct.h"
extern "C" { 
#include"head.h"
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}

UNICODE_STRING drvpath;
#define NT_QWORD_SIG_WIN10 ("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10")
#define NT_QWORD_MASK_WIN10 ("xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxx")

#define NT_QWORD_SIG_WIN11 ("\x48\x8B\x05\x2D\x7E\x06\x00")
#define NT_QWORD_MASK_WIN11 ("xxxxxxx")
#define SYSCALL_CODE 0xDFEB33F

enum operation : int
{
	memory_read = 0,
	memory_write,
	module_base,
	mget_cr3,
	mget_pe,
	mget_gaurded,
	check_driver,
	mouse_move,
};

struct INFO_T
{
	MOUSE_OBJECT mouse_obj = { 0 };
	bool success = false;
	unsigned int verification_code = 0;
	operation operation;
	HANDLE target_pid = 0;
	uint64_t    target_address;
	uint64_t    buffer_address;
	size_t size = 0;
	size_t return_size = 0;
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
__int64(__fastcall* oNtUserSetGestureConfig)(void* a1);

ULONGLONG s_target_pid = NULL;
static PEPROCESS s_target_process = NULL;
bool hasdeleted = false;
__int64 __fastcall hkNtUserSetGestureConfig(void* a1)
{
	if (reinterpret_cast<INFO_T*>(a1)->verification_code != SYSCALL_CODE)
		return oNtUserSetGestureConfig(a1);
	INFO_T* cmd = reinterpret_cast<INFO_T*>(a1);
	NTSTATUS StatusHandler;
	switch (cmd->operation) {
	case memory_read: {
		if (utils::CustomPsGetPEProcess((ULONGLONG)cmd->target_pid, &s_target_process) == STATUS_SUCCESS)
			{
	        StatusHandler = utils::readprocessmemory(s_target_process, (void*)cmd->target_address, (void*)cmd->buffer_address, cmd->size, &cmd->return_size);
			if (StatusHandler != STATUS_SUCCESS)
			{
				//
			}
			}
		cmd->success = true;
		break;
	}

	case memory_write: {
		if (utils::CustomPsGetPEProcess((ULONGLONG)cmd->target_pid, &s_target_process) == STATUS_SUCCESS)
		{
			StatusHandler = utils::writeprocessmemory(s_target_process, (void*)cmd->target_address, (void*)cmd->buffer_address, cmd->size, &cmd->return_size);
			if (StatusHandler != STATUS_SUCCESS)
			{
				//
			}
		}
		cmd->success = true;
		break;
	}

	case module_base: {
		if (utils::CustomPsGetPEProcess((ULONGLONG)cmd->target_pid, &s_target_process) == STATUS_SUCCESS)
		{
		    mma::get_process_module_information(cmd->target_pid, cmd->ModuleName,&cmd->ModuleBase,&cmd->PEB,&cmd->Entrypoint,&cmd->ModuleSize);
		}
		cmd->success = true;
		break;
	}
	case mget_cr3: {
		if (utils::CustomPsGetPEProcess((ULONGLONG)cmd->target_pid, &s_target_process) == STATUS_SUCCESS)
		{
			utils::save_process = 0;
			utils::eac_cr3 = utils::get_process_cr3(s_target_process);
		}
		cmd->success = true;
		break;
	}
	case mget_pe: {
		if (utils::CustomPsGetPEProcess((ULONGLONG)cmd->target_pid, &s_target_process) == STATUS_SUCCESS)
	   {
			s_target_pid = (ULONGLONG)cmd->target_pid;
	   }
		cmd->success = true;
		break;
	}
	case mget_gaurded:{
		cmd->allocation = utils::find_guarded_region();
		cmd->success = true;
		break;
	}
	case check_driver:
		cmd->allocation = 6666;
		cmd->success = true;
		break;
	case mouse_move:
		cmd->allocation = utils::setup_mouclasscallback(&cmd->mouse_obj);
		cmd->success = true;
	default: {
		cmd->success = false;
		break;
	}
	}

	return 0;
}
 uintptr_t nt_qword_deref;
NTSTATUS Initialize()
{
	const uintptr_t win32k = utils::get_kernel_module(skCrypt("win32k.sys"));
	uintptr_t nt_qword{};
	PEPROCESS process_target{};
	if (utils::find_process(skCrypt("explorer.exe"), &process_target) == STATUS_SUCCESS && process_target) {
		KeAttachProcess(process_target);
		if (win32k) {
			nt_qword = utils::find_pattern_image(win32k, NT_QWORD_SIG_WIN10, NT_QWORD_MASK_WIN10);
			nt_qword_deref = (uintptr_t)nt_qword + *(int*)((BYTE*)nt_qword + 3) + 7;
			*(void**)&oNtUserSetGestureConfig = _InterlockedExchangePointer((void**)nt_qword_deref, (void*)hkNtUserSetGestureConfig);
			KeDetachProcess();
		}
		else {

			return STATUS_UNSUCCESSFUL;
		}
	}
	else {

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}
extern "C" void DriverUnload(PDRIVER_OBJECT driver)
{
	UNICODE_STRING symbolic_link;
	RtlInitUnicodeString(&symbolic_link, (L"\\DosDevices\\Whoisthis"));
	IoDeleteSymbolicLink(&symbolic_link);
	IoDeleteDevice(driver->DeviceObject);
}
PDEVICE_OBJECT g_device_object = nullptr;


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING unicode)
{
	driver->DriverUnload = DriverUnload;
	g_device_object = driver->DeviceObject;
	UNICODE_STRING device_name; UNICODE_STRING chkfile;
	RtlInitUnicodeString(&device_name, (L"\\Device\\Whoisthis"));
	IoQueryFullDriverPath(driver, &drvpath);
	NTSTATUS status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status) || g_device_object == nullptr) return STATUS_UNSUCCESSFUL;

	UNICODE_STRING symbolic_link;
	RtlInitUnicodeString(&symbolic_link, (L"\\DosDevices\\Whoisthis"));
	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_device_object);
		return STATUS_UNSUCCESSFUL;
	}
	g_device_object->Flags |= DO_DIRECT_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;
	//DbgPrintEx(0, 0, skCrypt("[%s] Driver Loaded Successfully \n"), __FUNCTION__);
	Initialize();
	DelDriverFile(&drvpath);
	RtlInitUnicodeString(&chkfile, skCrypt(L"\\SystemRoot\\System32\\ntds.dat"));
	if (utils::CHECK_FILE(skCrypt(L"\\SystemRoot\\System32\\ntds.dat")) == TRUE)
	{
		DelDriverFile(&chkfile);
	}
	else { ObDereferenceObject(nullptr); }
	return STATUS_SUCCESS;
}
