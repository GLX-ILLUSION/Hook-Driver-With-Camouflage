//#include <ntifs.h>
//#include "Utils.h"
//#include "Crypter.h"
//
//#include "SelfDestruct.h"
//extern "C" { //undocumented windows internal functions (exported by ntoskrnl)
//#include"head.h"
//	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
//}
//
//constexpr ULONG init_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x775, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//constexpr ULONG read_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x776, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//constexpr ULONG write_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//constexpr ULONG g_module_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x778, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//constexpr ULONG guarded_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//constexpr ULONG get_cr3_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
//
//struct INFO_T
//{
//	HANDLE target_pid = 0;
//	uint64_t    target_address;
//	uint64_t    buffer_address;
//	size_t size = 0;
//	size_t return_size = 0;
//	LPCWSTR ModuleName = 0;
//	PVOID ModuleBase = 0;
//	ULONG ModuleSize = 0;
//	uintptr_t allocation;
//	long x;
//	long y;
//	unsigned short button_flags;
//};
//UNICODE_STRING dev_name, sym_link;
//PDEVICE_OBJECT dev_obj;
//ULONGLONG generalPID;
//UNICODE_STRING full_path;
//NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
//	UNREFERENCED_PARAMETER(device_obj);
//	NTSTATUS StatusHandler;
//	static PEPROCESS s_target_process = NULL;
//	irp->IoStatus.Information = sizeof(INFO_T);
//	auto IRPStack = IoGetCurrentIrpStackLocation(irp);
//	auto buffer = (INFO_T*)irp->AssociatedIrp.SystemBuffer;
//
//	if (IRPStack)
//	{
//		if (buffer && sizeof(*buffer) >= sizeof(INFO_T)) {
//			const auto ctl_code = IRPStack->Parameters.DeviceIoControl.IoControlCode;
//
//			if (ctl_code == init_code)
//			{
//				if (utils::CustomPsGetPEProcess((ULONGLONG)buffer->target_pid, &s_target_process) == STATUS_SUCCESS)
//				{
//					generalPID = (ULONGLONG)buffer->target_pid;
//				}
//			}
//			else if (ctl_code == read_code)
//			{
//				if (utils::CustomPsGetPEProcess(generalPID, &s_target_process) == STATUS_SUCCESS)
//				{
//					StatusHandler = utils::readprocessmemory(s_target_process, (void*)buffer->target_address, (void*)buffer->buffer_address, buffer->size, &buffer->return_size);
//					if (StatusHandler != STATUS_SUCCESS)
//					{
//						//	DbgPrintEx(0, 0, skCrypt("[%s] Couldn't Perform Operation at 0x%p \n"), __FUNCTION__, buffer->target_address);
//					}
//				}
//			}
//			else if (ctl_code == write_code)
//			{
//				if (utils::CustomPsGetPEProcess(generalPID, &s_target_process) == STATUS_SUCCESS)
//				{
//					StatusHandler = utils::writeprocessmemory(s_target_process, (void*)buffer->target_address, (void*)buffer->buffer_address, buffer->size, &buffer->return_size);  // old was writeprocessmemory
//					if (StatusHandler != STATUS_SUCCESS)
//					{
//						//	DbgPrintEx(0, 0, skCrypt("[%s] Couldn't Perform Operation at 0x%p \n"), __FUNCTION__ , buffer->target_address);
//					}
//				}
//			}
//			else if (ctl_code == g_module_code)
//			{
//				if (utils::CustomPsGetPEProcess(generalPID, &s_target_process) == STATUS_SUCCESS)
//				{
//					buffer->ModuleBase = mma::GetModuleBaseProcess(s_target_process, buffer->ModuleName);
//					buffer->ModuleSize = mma::MODULE_SIZE_IOCT;
//				}
//			}
//			else if (ctl_code == guarded_code)
//			{
//				buffer->allocation = utils::find_guarded_region();
//			}
//			else if (ctl_code == get_cr3_code)
//			{
//
//			}
//		}
//
//	}
//	IoCompleteRequest(irp, IO_NO_INCREMENT);
//	return STATUS_SUCCESS;
//}
//
//NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
//	UNREFERENCED_PARAMETER(device_obj);
//
//	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
//	IoCompleteRequest(irp, IO_NO_INCREMENT);
//	return irp->IoStatus.Status;
//}
//
//NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
//	UNREFERENCED_PARAMETER(device_obj);
//
//	IoCompleteRequest(irp, IO_NO_INCREMENT);
//	return irp->IoStatus.Status;
//}
//
//NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
//	UNREFERENCED_PARAMETER(device_obj);
//
//	IoCompleteRequest(irp, IO_NO_INCREMENT);
//	return irp->IoStatus.Status;
//}
//
//VOID Unload_io(PDRIVER_OBJECT DriverObject) {
//	if (dev_obj != nullptr)
//	{
//		IoDeleteSymbolicLink(&sym_link);
//		IoDeleteDevice(dev_obj);
//
//	}
//}
//#define  BUFFER_SIZE 7
//BOOL CHECK_FILE(PCWSTR FILE_NAME)
//{
//	LARGE_INTEGER      byteOffset;
//	CHAR     buffer[BUFFER_SIZE];
//	size_t  cb;
//	UNICODE_STRING     uniName;
//	OBJECT_ATTRIBUTES  objAttr;
//	HANDLE   handle;
//	NTSTATUS ntstatus;
//	IO_STATUS_BLOCK    ioStatusBlock;
//	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
//		return STATUS_INVALID_DEVICE_STATE;
//	RtlInitUnicodeString(&uniName, FILE_NAME);
//	InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
//	ntstatus = ZwCreateFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
//	if (!NT_SUCCESS(ntstatus))
//	{
//
//		ZwClose(handle); return FALSE;
//	}
//	else { ZwClose(handle); return TRUE; }
//
//}
//
//#define NT_QWORD_SIG_WIN10 ("\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x38\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x38\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x10")
//#define NT_QWORD_MASK_WIN10 ("xxx????xxxxxxxxx?xxxx?xx????xxxxxxxxxxxxxxxxxxx????xxxxx")
//#define SYSCALL_CODE 0xDEADBEEF
//
//enum operation : int
//{
//	memory_read = 0,
//	memory_write,
//	module_base,
//};
//
//struct cmd_t
//{
//	bool success = false;
//	unsigned int verification_code = 0;
//	operation operation;
//	void* buffer;
//	ULONG64	address;
//	ULONG size;
//	ULONG pid;
//	const char* module_name;
//	ULONG64 base_address;
//};
//__int64(__fastcall* oNtUserSetGestureConfig)(void* a1);
//
//__int64 __fastcall hkNtUserSetGestureConfig(void* a1)
//{
//	if (reinterpret_cast<cmd_t*>(a1)->verification_code != SYSCALL_CODE)
//		return oNtUserSetGestureConfig(a1);
//
//	cmd_t* cmd = reinterpret_cast<cmd_t*>(a1);
//
//	switch (cmd->operation) {
//	case memory_read: {
//		DbgPrintEx(0, 0, skCrypt("[%s] Driver Read  \n"), __FUNCTION__);
//		//mem::read_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
//		cmd->success = true;
//		break;
//	}
//
//	case memory_write: {
//		DbgPrintEx(0, 0, skCrypt("[%s] Driver Write  \n"), __FUNCTION__);
//		//mem::write_physical_memory((HANDLE)cmd->pid, (PVOID)cmd->address, cmd->buffer, cmd->size);
//		cmd->success = true;
//		break;
//	}
//
//	case module_base: {
//		DbgPrintEx(0, 0, skCrypt("[%s] Driver Base  \n"), __FUNCTION__);
//		//cmd->base_address = mem::get_module_base_address(cmd->pid, cmd->module_name);
//		cmd->success = true;
//		break;
//	}
//
//	default: {
//		DbgPrintEx(0, 0, skCrypt("[%s] Driver No OP  \n"), __FUNCTION__);
//		cmd->success = false;
//		break;
//	}
//	}
//
//	return 0;
//}
//NTSTATUS StartUp()
//{
//	const uintptr_t win32k = utils::get_kernel_module(("win32k.sys"));
//	uintptr_t nt_qword{};
//	PEPROCESS process_target{};
//	if (utils::find_process(("explorer.exe"), &process_target) == STATUS_SUCCESS && process_target) {
//		KeAttachProcess(process_target);
//		if (win32k) {
//			nt_qword = utils::find_pattern_image(win32k, NT_QWORD_SIG_WIN10, NT_QWORD_MASK_WIN10);
//			DbgPrintEx(0, 0, skCrypt("[%s]  win32k.sys @ 0x%p \n"), __FUNCTION__, win32k);
//			DbgPrintEx(0, 0, skCrypt("[%s] nt_qword @ 0x%p \n"), __FUNCTION__, nt_qword);
//
//			const uintptr_t nt_qword_deref = (uintptr_t)nt_qword + *(int*)((BYTE*)nt_qword + 3) + 7;
//			DbgPrintEx(0, 0, skCrypt("[%s] *nt_qword @ 0x%p \n"), __FUNCTION__, nt_qword_deref);
//			*(void**)&oNtUserSetGestureConfig = _InterlockedExchangePointer((void**)nt_qword_deref, (void*)hkNtUserSetGestureConfig);
//			KeDetachProcess();
//		}
//		else {
//			DbgPrintEx(0, 0, skCrypt("[%s] win32k.sys not found \n"), __FUNCTION__);
//
//			return STATUS_UNSUCCESSFUL;
//		}
//	}
//	else {
//		DbgPrintEx(0, 0, skCrypt("[%s] explorer not found \n"), __FUNCTION__);
//
//		return STATUS_UNSUCCESSFUL;
//	}
//
//	/*
//	if (!utils::clear_ci()) {
//		printf("[-] Unable to clear CI");
//		return STATUS_UNSUCCESSFUL;
//	}
//	*/
//	return STATUS_SUCCESS;
//}
//
//#define HideDrvPath L"\\??\\C:\\DriverWheels.sys"
//#define ADrvPath L"\\??\\C:\\DriverWheels.sys"
//#define ODrvPath L"\\??\\C:\\vgk.sys"
//#define ServiceName  L"Vanguard"
//extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING regpath) {
//	UNREFERENCED_PARAMETER(driver_obj);
//	UNREFERENCED_PARAMETER(regpath);
//	RtlInitUnicodeString(&dev_name, L"\\Device\\cartidriver");
//	auto status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
//	if (status != STATUS_SUCCESS) return status;
//	RtlInitUnicodeString(&sym_link, L"\\DosDevices\\cartidriver");
//	status = IoCreateSymbolicLink(&sym_link, &dev_name);
//	if (status != STATUS_SUCCESS) return status;
//
//	SetFlag(dev_obj->Flags, DO_BUFFERED_IO);
//
//	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
//		driver_obj->MajorFunction[t] = unsupported_io;
//
//
//	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
//	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
//	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
//	driver_obj->DriverUnload = Unload_io;
//
//	ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
//
//	DbgPrintEx(0, 0, skCrypt("[%s] Driver Loaded Successfully \n"), __FUNCTION__);
//	UNICODE_STRING chckfile;
//	RtlInitUnicodeString(&chckfile, skCrypt(L"\\SystemRoot\\System32\\ntds.dat"));
//	if (CHECK_FILE(skCrypt(L"\\SystemRoot\\System32\\ntds.dat")) == TRUE) 
//	{
//	DelDriverFile(&chckfile);
//	} else{ ObDereferenceObject(nullptr); }
//	Driver = driver_obj;
//	/*if (InitAllOffSet()) 
//	{
//		CamouflageDrvLoad(ADrvPath, ODrvPath, ServiceName);
//	}*/
//
//	return STATUS_SUCCESS;
//}