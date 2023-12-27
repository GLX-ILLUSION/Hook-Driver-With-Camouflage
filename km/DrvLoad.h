#pragma once
#include<ntifs.h>

#define DrvObjNamePrefix L"\\Driver\\"
#define ServiceRegistryPath L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define WDF "WDFLDR.SYS"

typedef struct _ShellContext {
	PDRIVER_OBJECT DrvObj;
	PUNICODE_STRING PSTR;
}ShellContext, * PShellContext;

typedef struct _LDR_DATA_TABLE_ENTRYX {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG32 Flags;
}LDR_DATA_TABLE_ENTRYX, * PLDR_DATA_TABLE_ENTRYX;


ULONG64 CIFun;
PULONG64 Pqword_14040EF40;
PIMAGE_NT_HEADERS(*RtlImageNtHeader)(PVOID DllBase);

NTSTATUS(*MiGenerateSystemImageNames)(PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PUNICODE_STRING OutUnicode, PUNICODE_STRING OutUnicode14, PUNICODE_STRING String1);
NTSTATUS(*MiObtainSectionForDriver)(PUNICODE_STRING String1, PUNICODE_STRING DriverPath, ULONG64 zero1, ULONG64 zero2, PULONG64 PDriverSection);

PUCHAR(*MiGetSystemAddressForImage)(PVOID PSECTION, int zero, int* un);

NTSTATUS(*MiMapSystemImage)(PVOID PSECTION, PUCHAR BaseVa);

PUCHAR(*RtlImageDirectoryEntryToData)(PUCHAR DllBase, ULONG64 one, ULONG64 one1, PULONG32 PSize);

NTSTATUS(*MiSnapThunk)(PUCHAR importDllBase, PUCHAR DllBase, PULONG64 PITE, PULONG64 PIATE, ULONG64 zero);

PKTHREAD(*MmAcquireLoadLock)();

VOID(*MmReleaseLoadLock)(PKTHREAD thread);

ULONG64(*MiFillPteHierarchy)(ULONG64 va, PPTE_HIERARCHY Pout);

VOID(*IopReadyDeviceObjects)(PDRIVER_OBJECT DrvObj);

NTSTATUS(*ShellDriverEntry)(PVOID a, PVOID b);



ULONG64 SectionOffset;
PLIST_ENTRY64 PsLoadedModuleList;
ULONG64 BaseDllNameOffset;
ULONG64 DllBaseOffset;
ULONG64 SizeOfImageOffset;
ULONG64 FlagsOffset;


//----------------------

PULONG64 PIoDriverObjectType;

ULONG64 PIopDriverLoadResource;

ULONG64 PIopInvalidDeviceRequest;

NTSTATUS(*ObCreateObjectEx)(BOOLEAN AccMode, ULONG64 Type, POBJECT_ATTRIBUTES attributes, ULONG64 zero, PULONG64 Out, ULONG64 Size, ULONG64 zero1, ULONG64 zero2, PVOID PObject, ULONG64 zero3);

NTSTATUS(*ObInsertObjectEx)(PVOID PObject, ULONG64 zero, ULONG64 one, ULONG64 zero1, ULONG64 zero2, ULONG64 zero3, PHANDLE PHandle);

NTSTATUS(*MiConstructLoaderEntry)(PLDR_DATA_TABLE_ENTRYX DriverSection,
	PUNICODE_STRING DrvName,//"XXX.sys"
	PUNICODE_STRING DrvPath,//
	ULONG64 zero,
	ULONG64 one,
	PVOID PnewDriverSection);

ULONG64 PCmRegistryMachineHardwareDescriptionSystemName;

VOID LoadDrv(PWCHAR DrvPath);
BOOLEAN CamouflageDrvLoad(PWCHAR ADrvPath, PWCHAR ODrvPath, PWCHAR ServiceName);
