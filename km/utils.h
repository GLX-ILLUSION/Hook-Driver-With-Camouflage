
#include "defines.h"
#include <ntimage.h>
#include "Crypter.h"

namespace utils
{
#define  BUFFER_SIZE 7
uint64_t eac_cr3 = 0;
    BOOL CHECK_FILE(PCWSTR FILE_NAME)
    {
      
        LARGE_INTEGER      byteOffset;
        CHAR     buffer[BUFFER_SIZE];
        size_t  cb;
        UNICODE_STRING     uniName;
        OBJECT_ATTRIBUTES  objAttr;
        HANDLE   handle;
        NTSTATUS ntstatus;
        IO_STATUS_BLOCK    ioStatusBlock;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return STATUS_INVALID_DEVICE_STATE;
        RtlInitUnicodeString(&uniName, FILE_NAME);
        InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        ntstatus = ZwCreateFile(&handle, GENERIC_READ, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
        if (!NT_SUCCESS(ntstatus))
        {

            ZwClose(handle); return FALSE;
        }
        else { ZwClose(handle); return TRUE; }
    
    }
    bool pattern_check(const char* data, const char* pattern, const char* mask)
    {
        size_t len = strlen(mask);

        for (size_t i = 0; i < len; i++)
        {
            if (data[i] == pattern[i] || mask[i] == '?')
                continue;
            else
                return false;
        }

        return true;
    }
    DWORD64 find_pattern(DWORD64 addr, DWORD32 size, const char* pattern, const char* mask)
    {
        size -= (DWORD32)strlen(mask);

        for (DWORD32 i = 0; i < size; i++)
        {
            if (pattern_check((const char*)addr + i, pattern, mask))
                return addr + i;
        }

        return 0;
    }

    DWORD64 find_pattern_image(DWORD64 addr, const char* pattern, const char* mask)
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

        for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER p = &section[i];

            if (strstr((const char*)p->Name, ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
            {
                DWORD64 res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
                if (res) return res;
            }
        }

        return 0;
    }
    NTSTATUS find_process(char* process_name, PEPROCESS* process)
    {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        char image_name[15];

        do {
            RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)curr_entry + 0x5a8), sizeof(image_name));

            if (strstr(image_name, process_name)) {
                DWORD active_threads;
                RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));
                if (active_threads) {
                    *process = curr_entry;
                    return STATUS_SUCCESS;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

        } while (curr_entry != sys_process);

        return STATUS_NOT_FOUND;
    }
    PHYSICAL_ADDRESS SafeMmGetPhysicalAddress(PVOID BaseAddress)
    {
        static BOOLEAN* KdEnteredDebugger = 0;
        if (!KdEnteredDebugger)
        {
            UNICODE_STRING UniCodeFunctionName = RTL_CONSTANT_STRING(L"KdEnteredDebugger");
            KdEnteredDebugger = reinterpret_cast<BOOLEAN*>(MmGetSystemRoutineAddress(&UniCodeFunctionName));
        }

        *KdEnteredDebugger = FALSE;
        PHYSICAL_ADDRESS PhysicalAddress = MmGetPhysicalAddress(BaseAddress);
        *KdEnteredDebugger = TRUE;

        return PhysicalAddress;
    }
    inline ULONG RandomNumber()
    {
        ULONG64 tickCount;
        KeQueryTickCount(&tickCount);
        return RtlRandomEx((PULONG)&tickCount);
    }

    void WriteRandom(ULONG64 addr, ULONG size)
    {
        for (size_t i = 0; i < size; i++)
        {
            *(char*)(addr + i) = RandomNumber() % 255;
        }
    }

    auto get_system_information(const SYSTEM_INFORMATION_CLASS information_class) -> const void*
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation(information_class, buffer, size, &size);

        const auto info = ExAllocatePool(NonPagedPool, size);

        if (!info)
        {
            return nullptr;
        }

        if (ZwQuerySystemInformation(information_class, info, size, &size) != STATUS_SUCCESS)
        {
            ExFreePool(info);
            return nullptr;
        }

        return info;
    }

    auto get_kernel_module(const char* name) -> const uintptr_t
    {
        const auto to_lower = [](char* string) -> const char* {
            for (char* pointer = string; *pointer != '\0'; ++pointer)
            {
                *pointer = (char)(short)tolower(*pointer);
            }

            return string;
        };

        const auto info = (PRTL_PROCESS_MODULES)get_system_information(system_module_information);

        if (!info)
        {
            return 0;
        }

        for (auto i = 0ull; i < info->number_of_modules; ++i)
        {
            const auto& module = info->modules[i];

            if (strcmp(to_lower((char*)module.full_path_name + module.offset_to_file_name), name) == 0)
            {
                const auto address = module.image_base;

                ExFreePool(info);

                return reinterpret_cast<uintptr_t> (address);
            }
        }

        ExFreePool(info);

        return 0;
    }
    auto find_guarded_region() -> UINT_PTR
    {
        PSYSTEM_BIGPOOL_INFORMATION pool_information = 0;

        ULONG information_length = 0;
        NTSTATUS status = ZwQuerySystemInformation(system_bigpool_information, &information_length, 0, &information_length);

        while (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            if (pool_information)
                ExFreePool(pool_information);

            pool_information = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, information_length);
            status = ZwQuerySystemInformation(system_bigpool_information, pool_information, information_length, &information_length);
        }
        UINT_PTR saved_virtual_address = 0;

        if (pool_information)
        {
            for (ULONG i = 0; i < pool_information->Count; i++)
            {
                SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];

                UINT_PTR virtual_address = (UINT_PTR)allocation_entry->VirtualAddress & ~1ull;

                if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
                {
                    if (saved_virtual_address == 0 && allocation_entry->TagUlong == 'TnoC') {
                        saved_virtual_address = virtual_address;
                    }
                }
            }
            ExFreePool(pool_information);
        }
        return saved_virtual_address;
    }
    DWORD getoffsets()
    {
        RTL_OSVERSIONINFOW ver = { 0 };
        RtlGetVersion(&ver);

        switch (ver.dwBuildNumber)
        {
        case WINDOWS_1803:
            return 0x0278;
            break;
        case WINDOWS_1809:
            return 0x0278;
            break;
        case WINDOWS_1903:
            return 0x0280;
            break;
        case WINDOWS_1909:
            return 0x0280;
            break;
        case WINDOWS_2004:
            return 0x0388;
            break;
        case WINDOWS_20H2:
            return 0x0388;
            break;
        case WINDOWS_21H1:
            return 0x0388;
            break;
        default:
            return 0x0388;
        }
    }
    auto getprocessdirbase(PEPROCESS targetprocess) -> ULONG_PTR
    {
        if (!targetprocess)
            return 0;

        PUCHAR process = (PUCHAR)targetprocess;
        ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28);
        if (process_dirbase == 0)
        {
            auto userdiroffset = getoffsets();
            ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + userdiroffset);
            return process_userdirbase;
        }
        return process_dirbase;
    }

    auto readphysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
    {
        const auto irql = __readcr8();
        KeRaiseIrqlToDpcLevel();
        if (!address)
        {
            __writecr8(irql);
            return STATUS_UNSUCCESSFUL;
        }
        MM_COPY_ADDRESS addr = { 0 };
        addr.PhysicalAddress.QuadPart = (LONGLONG)address;
        __writecr8(irql);
        return MmCopyMemory(buffer, addr, size, MM_COPY_MEMORY_PHYSICAL, read);
    }

    auto writephysaddress(PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written) -> NTSTATUS
    {
        const auto irql = __readcr8();
        KeRaiseIrqlToDpcLevel();
        if (!address)
        {
            __writecr8(irql);
            return STATUS_UNSUCCESSFUL;
        }
        PHYSICAL_ADDRESS addr = { 0 };
        addr.QuadPart = (LONGLONG)address;

        auto mapped_mem = MmMapIoSpaceEx(addr, size, PAGE_READWRITE);

        if (!mapped_mem)
        {
            __writecr8(irql);
            return STATUS_UNSUCCESSFUL;
        }

        memcpy(mapped_mem, buffer, size);

        *written = size;
        MmUnmapIoSpace(mapped_mem, size);
        __writecr8(irql);
        return STATUS_SUCCESS;
    }


    auto translateaddress(uint64_t processdirbase, uint64_t address) -> uint64_t
    {
        processdirbase &= ~0xf;

        uint64_t pageoffset = address & ~(~0ul << PAGE_OFFSET_SIZE);
        uint64_t pte = ((address >> 12) & (0x1ffll));
        uint64_t pt = ((address >> 21) & (0x1ffll));
        uint64_t pd = ((address >> 30) & (0x1ffll));
        uint64_t pdp = ((address >> 39) & (0x1ffll));

        SIZE_T readsize = 0;
        uint64_t pdpe = 0;
        readphysaddress((void*)(processdirbase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
        if (~pdpe & 1)
            return 0;

        uint64_t pde = 0;
        readphysaddress((void*)((pdpe & mask) + 8 * pd), &pde, sizeof(pde), &readsize);
        if (~pde & 1)
            return 0;

        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

        uint64_t ptraddr = 0;
        readphysaddress((void*)((pde & mask) + 8 * pt), &ptraddr, sizeof(ptraddr), &readsize);
        if (~ptraddr & 1)
            return 0;

        if (ptraddr & 0x80)
            return (ptraddr & mask) + (address & ~(~0ull << 21));

        address = 0;
        readphysaddress((void*)((ptraddr & mask) + 8 * pte), &address, sizeof(address), &readsize);
        address &= mask;

        if (!address)
            return 0;
        return address + pageoffset;
    }

    auto readprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* read) -> NTSTATUS
    {
        auto process_dirbase = eac_cr3;
        if (eac_cr3 > 0)
        {
            SIZE_T curoffset = 0;
            while (size)
            {
                auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
                if (!addr) return STATUS_UNSUCCESSFUL;
                ULONG64 readsize = min(PAGE_SIZE - (addr & 0xFFF), size);
                SIZE_T readreturn = 0;
                auto readstatus = readphysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), readsize, &readreturn);
                size -= readreturn;
                curoffset += readreturn;
                if (readstatus != STATUS_SUCCESS) break;
                if (readreturn == 0) break;
            }

            *read = curoffset;
        }
        else { return STATUS_UNSUCCESSFUL; }

        return STATUS_SUCCESS;
    }

    auto writeprocessmemory(PEPROCESS process, PVOID address, PVOID buffer, SIZE_T size, SIZE_T* written) -> NTSTATUS
    {
        auto process_dirbase = eac_cr3;
        if (eac_cr3 > 0)
        {
            SIZE_T curoffset = 0;
            SIZE_T TotalSize = size;
            while (size)
            {
                auto addr = translateaddress(process_dirbase, (ULONG64)address + curoffset);
                if (!addr) return STATUS_UNSUCCESSFUL;

                ULONG64 writesize = min(PAGE_SIZE - (addr & 0xFFF), size);
                SIZE_T written = 0;
                auto writestatus = writephysaddress((void*)addr, (PVOID)((ULONG64)buffer + curoffset), writesize, &written);
                size -= written;
                TotalSize -= written;
                curoffset += written;
                if (writestatus != STATUS_SUCCESS) break;
                if (written == 0) break;
            }

            *written = curoffset;
        }
        else { return STATUS_UNSUCCESSFUL; }
        return STATUS_SUCCESS;
    }
    auto setup_mouclasscallback(PMOUSE_OBJECT mouse_obj) -> NTSTATUS
    {
        UNICODE_STRING mouclass;
        RtlInitUnicodeString(&mouclass, L"\\Driver\\MouClass");

        PDRIVER_OBJECT mouclass_obj = NULL;
        NTSTATUS status = ObReferenceObjectByName(&mouclass, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&mouclass_obj);

        UNICODE_STRING mouhid;
        RtlInitUnicodeString(&mouhid, L"\\Driver\\MouHID");

        PDRIVER_OBJECT mouhid_obj = NULL;
        status = ObReferenceObjectByName(&mouhid, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&mouhid_obj);

        PDEVICE_OBJECT mouhid_deviceobj = mouhid_obj->DeviceObject;

        while (mouhid_deviceobj && !mouse_obj->service_callback)
        {
            PDEVICE_OBJECT mouclass_deviceobj = mouclass_obj->DeviceObject;
            while (mouclass_deviceobj && !mouse_obj->service_callback)
            {
                if (!mouclass_deviceobj->NextDevice && !mouse_obj->mouse_device)
                {
                    mouse_obj->mouse_device = mouclass_deviceobj;
                }

                PULONG_PTR deviceobj_extension = (PULONG_PTR)mouhid_deviceobj->DeviceExtension;
                ULONG_PTR deviceobj_ext_size = ((ULONG_PTR)mouhid_deviceobj->DeviceObjectExtension - (ULONG_PTR)mouhid_deviceobj->DeviceExtension) / 4;

                for (ULONG_PTR i = 0; i < deviceobj_ext_size; i++)
                {
                    if (deviceobj_extension[i] == (ULONG_PTR)mouclass_deviceobj && deviceobj_extension[i + 1] > (ULONG_PTR)mouclass_obj)
                    {
                        mouse_obj->service_callback = (MouseClassServiceCallback)(deviceobj_extension[i + 1]);
                        break;
                    }
                }
                mouclass_deviceobj = mouclass_deviceobj->NextDevice;
            }
            mouhid_deviceobj = mouhid_deviceobj->AttachedDevice;
        }

        if (!mouse_obj->mouse_device)
        {
            PDEVICE_OBJECT target_device_object = mouclass_obj->DeviceObject;
            while (target_device_object)
            {
                if (!target_device_object->NextDevice)
                {
                    mouse_obj->mouse_device = target_device_object;
                    break;
                }
                target_device_object = target_device_object->NextDevice;
            }
        }

        ObDereferenceObject(mouclass_obj);
        ObDereferenceObject(mouhid_obj);

        return status;
    }
    typedef union _virt_addr_t
    {
        void* value;
        struct
        {
            uint64_t offset : 12;
            uint64_t pt_index : 9;
            uint64_t pd_index : 9;
            uint64_t pdpt_index : 9;
            uint64_t pml4_index : 9;
            uint64_t reserved : 16;
        };
    } virt_addr_t, * pvirt_addr_t;
//#define V32(eacaddress) ((((unsigned __int64)eacaddress^ ((_QWORD)&eacaddress << 13)) >> 7) ^ (unsigned __int64)eacaddress^ ((_QWORD)eacaddress<< 13))
//#define V33(eacaddress) (V32(eacaddress) ^ (V32(eacaddress) << 17))
//#define decrypt_cr3(cr3, key,eacaddress) (cr3 & 0xBFFF000000000FFF | (((key ^ V33(eacaddress) ^ (V33(eacaddress) << 32)) & 0xFFFFFFFFF) << 12))



    bool is_dirbase_invalid(uint64_t cr3)
    {
        //DbgPrintEx(0, 0, ("[%s] CR3 bit: %x \n"), __FUNCTION__, (cr3 >> 0x38));
        if ((cr3 >> 0x38) == 0x40)
        {
            return true;
        }
        if ((cr3 >> 0x38) == 0xFF)
        {
            return true;
        }
    }

    PEPROCESS save_process = 0;

#define decrypt_cr3(cr3, key) (cr3 & 0xBFFF000000000FFF | ((__ROR8__(key, 19) & 0xFFFFFFFFF) << 12))
    uintptr_t get_process_cr3(PEPROCESS pe_process)
    {
        uintptr_t process_dirbase = *(uintptr_t*)((uint8_t*)pe_process + 0x28);

        if (process_dirbase == 0)
            process_dirbase = *(uintptr_t*)((uint8_t*)pe_process + 0x388);

        if (is_dirbase_invalid(process_dirbase))
        {
            if (save_process != pe_process)
            {
                uint64_t eac_module = (uint64_t)(get_kernel_module(skCrypt("easyanticheat_eos.sys"))); // easyanticheat_eos.sys
               
                if (!eac_module)
                {
                    return process_dirbase;
                }

                
                // F0 4C 0F C1 1D ? ? ? ?   "\x48\xC1\xE7\x05\x4A\x39\x74\x1F\x0C","xxxxxxxxx");
                int64_t offset = *(int64_t*)(eac_module + 0x188D58);//(eac_module + 0x1850B0); //old 0x1850B0 // new 0x188D58
                //DbgPrintEx(0, 0, ("[%s] Offset1 : %p \n"), __FUNCTION__, offset);
                //DbgPrintEx(0, 0, ("[%s] Location1 : %p \n"), __FUNCTION__, Loc1);
                if (offset)
                {
                    uint64_t data_offset = (offset & 0xFFFFFFFFF) << 12;
                    uint64_t data = ((0xFFFFull << 48) + data_offset);
                    uint64_t key = *(uint64_t*)(data + 0x14);

                    if (!key)
                        return process_dirbase;

                    eac_cr3 = decrypt_cr3(process_dirbase, key);
                    //DbgPrintEx(0, 0, ("[%s] Fixed CR3  #1(Main) : %p \n"), __FUNCTION__, eac_cr3);
                }
                else { 
                   // DbgPrintEx(0, 0, ("[%s]invalid offset #1: %p \n"), __FUNCTION__, offset); 
                    return process_dirbase; }
                save_process = pe_process;
                }

            if (save_process == pe_process)
            {
                process_dirbase = eac_cr3;
              //  //DbgPrintEx(0, 0, ("[%s] Returning Valid CR3 %p \n"), __FUNCTION__, process_dirbase);
            }
              
        }
        else { eac_cr3 = process_dirbase; }
        return process_dirbase;
    }

    
    extern "C" NTKERNELAPI PEPROCESS PsInitialSystemProcess;

    NTSTATUS CustomPsGetPEProcess(
        _In_ ULONGLONG ProcessId,
        _Out_ PEPROCESS* ProcessOut
    )
    {
        PEPROCESS InitialProcess = PsInitialSystemProcess;
        PEPROCESS Process = InitialProcess;

        while (TRUE)
        {
            if (*(PUINT64)((UINT64)Process + 0x440) == ProcessId) // EPROCESS->UniqueProcessId  dt nt!_eprocess
            {
                *ProcessOut = Process;
                return STATUS_SUCCESS;
            }

            PLIST_ENTRY List = (PLIST_ENTRY)((uintptr_t)Process + 0x448); // EPROCESS->ActiveProcessLinks
            Process = (PEPROCESS)((uintptr_t)List->Flink - 0x448);

            if (Process == NULL ||
                Process == InitialProcess)
            {
                break;
            }
        }

        return STATUS_NOT_FOUND;
    }
}
namespace clearpdb
{

    //Win 11
    ULONG PiDDBCacheTableOffset = 0xD53D50;
    ULONG PiDDBLockOffset = 0xC5C500; 
    ULONG g_KernelHashBucketListOffset = 0xCF088;
    ULONG g_HashCacheLockOffset = 0x391E0;
    ULONG g_CiEaCacheLookasideListOffset = 0x38680;
    void RemoveMmUnloadedDrivers(PDRIVER_OBJECT driverObject)
    {
        reinterpret_cast<PKLDR_DATA_TABLE_ENTRY>(driverObject->DriverSection)->BaseDllName.Length = 0; // mm unloaded drivers entry is not created if base dll name is 0
    }

#pragma region PiDDBCacheTable



    NTSTATUS RemovePiDDBCacheTableEntry(PDRIVER_OBJECT driverObject)
    {
        //get table and lock addresses
        ULONG64 kernelBase = (ULONG64)utils::get_kernel_module("ntoskrnl.exe");
        PRTL_AVL_TABLE PiDDBCacheTable = PRTL_AVL_TABLE(kernelBase + PiDDBCacheTableOffset);
        PERESOURCE PiDDBLock = PERESOURCE(kernelBase + PiDDBLockOffset);

        //create lookup entry
        PiDDBCacheEntry lookupEntry;
        RtlInitUnicodeString(&lookupEntry.driverName, PKLDR_DATA_TABLE_ENTRY(driverObject->DriverSection)->BaseDllName.Buffer);

        //get spinlock
        if (!ExAcquireResourceExclusiveLite(PiDDBLock, true))
        {
            return STATUS_UNSUCCESSFUL;
        }

        //look for entry
        PiDDBCacheEntry* foundEntry = (PiDDBCacheEntry*)(RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry));


        if (!foundEntry)
        {
            ExReleaseResourceLite(PiDDBLock);
            return STATUS_UNSUCCESSFUL;
        }

        //get prev and next list entries to remove our entry from list
        PLIST_ENTRY nextEntry = foundEntry->list.Flink;
        PLIST_ENTRY prevEntry = foundEntry->list.Blink;

        if (!nextEntry || !prevEntry)
        {
            ExReleaseResourceLite(PiDDBLock);
            return STATUS_UNSUCCESSFUL;
        }

        //replace links
        prevEntry->Flink = foundEntry->list.Flink;
        nextEntry->Blink = foundEntry->list.Blink;

        foundEntry->list.Blink = prevEntry;
        foundEntry->list.Flink = nextEntry;


        //clean entry
        utils::WriteRandom((ULONG64)foundEntry->driverName.Buffer, foundEntry->driverName.Length);
        foundEntry->driverStamp = utils::RandomNumber() % sizeof(ULONG);
        utils::WriteRandom((ULONG64)&foundEntry->list, sizeof(LIST_ENTRY));
        foundEntry->loadStatus = utils::RandomNumber() % sizeof(NTSTATUS);
        RtlDeleteElementGenericTableAvl(PiDDBCacheTable, foundEntry);

        //check if entry can still be found
        foundEntry = (PiDDBCacheEntry*)(RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry));

        if (foundEntry)
        {
            ExReleaseResourceLite(PiDDBLock);
            return STATUS_UNSUCCESSFUL;
        }

        ExReleaseResourceLite(PiDDBLock);
        return STATUS_SUCCESS;
    }
#pragma endregion

#pragma region HashBucketList

    typedef struct _HashBucketEntry
    {
        struct _HashBucketEntry* Next;
        UNICODE_STRING DriverName;
        ULONG CertHash[5];
    } HashBucketEntry;

    NTSTATUS RemoveKernelHashBucketListEntry(PDRIVER_OBJECT driverObject)
    {
        UINT64 cidllBase = utils::get_kernel_module("CI.dll");
        if (!cidllBase)
        {
            return STATUS_UNSUCCESSFUL;
        }

        PSINGLE_LIST_ENTRY g_KernelHashBucketList = PSINGLE_LIST_ENTRY(cidllBase + g_KernelHashBucketListOffset);
        PERESOURCE g_HashCacheLock = PERESOURCE(cidllBase + g_HashCacheLockOffset);

        UNICODE_STRING driverName;
        RtlInitUnicodeString(&driverName, PKLDR_DATA_TABLE_ENTRY(driverObject->DriverSection)->FullDllName.Buffer + 6); //remove \??\C:

        if (!ExAcquireResourceExclusiveLite(g_HashCacheLock, true))
        {
            return STATUS_UNSUCCESSFUL;
        }

        HashBucketEntry* currEntry = (HashBucketEntry*)g_KernelHashBucketList->Next;
        HashBucketEntry* prevEntry = (HashBucketEntry*)g_KernelHashBucketList;

        while (currEntry)
        {
            if (!RtlCompareUnicodeString(&driverName, &currEntry->DriverName, true))
            {
                //unlink
                prevEntry->Next = currEntry->Next;

                //overwrite
                currEntry->Next = (HashBucketEntry*)(utils::RandomNumber() % sizeof(PVOID));
                utils::WriteRandom((UINT64)&currEntry->CertHash, sizeof(currEntry->CertHash));
                utils::WriteRandom((ULONG64)currEntry->DriverName.Buffer, currEntry->DriverName.Length);

                //free 
                ExFreePoolWithTag(currEntry, 0);
                break;
            }

            prevEntry = currEntry;
            currEntry = currEntry->Next;
        }

        currEntry = (HashBucketEntry*)g_KernelHashBucketList->Next;
        while (currEntry)
        {
            if (!RtlCompareUnicodeString(&driverName, &currEntry->DriverName, true))
            {

                ExReleaseResourceLite(g_HashCacheLock);
                return STATUS_UNSUCCESSFUL;
            }
            currEntry = currEntry->Next;
        }

        ExReleaseResourceLite(g_HashCacheLock);
        return STATUS_SUCCESS;
    }

#pragma endregion

#pragma region LookasideList

    NTSTATUS DeleteCiEaCacheLookasideList()
    {
        UINT64 cidllBase = utils::get_kernel_module("CI.dll");
        if (!cidllBase)
        {

            return STATUS_UNSUCCESSFUL;
        }


        PLOOKASIDE_LIST_EX g_CiEaCacheLookasideList = (PLOOKASIDE_LIST_EX)(cidllBase + g_CiEaCacheLookasideListOffset);
        ULONG size = g_CiEaCacheLookasideList->L.Size;
        ExDeleteLookasideListEx(g_CiEaCacheLookasideList);
        ExInitializeLookasideListEx(g_CiEaCacheLookasideList, NULL, NULL, PagedPool, 0, size, 'csIC', 0);
    }

#pragma endregion
}

EXTERN_C{ NTKERNELAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process); }

namespace mma
{
    uintptr_t OldProcess;

    void CopyList(IN PLIST_ENTRY Original, IN PLIST_ENTRY Copy, IN KPROCESSOR_MODE Mode)
    {
        if (IsListEmpty(&Original[Mode]))
        {
            InitializeListHead(&Copy[Mode]);
        }
        else
        {
            Copy[Mode].Flink = Original[Mode].Flink;
            Copy[Mode].Blink = Original[Mode].Blink;
            Original[Mode].Flink->Blink = &Copy[Mode];
            Original[Mode].Blink->Flink = &Copy[Mode];
        }
    }
    void MoveApcState(PKAPC_STATE OldState, PKAPC_STATE NewState)
    {
        RtlCopyMemory(NewState, OldState, sizeof(KAPC_STATE));

        CopyList(OldState->ApcListHead, NewState->ApcListHead, KernelMode);
        CopyList(OldState->ApcListHead, NewState->ApcListHead, UserMode);
    }
    uint64_t CR3 = NULL;
    uint64_t OldCR3 = NULL;
    void AttachProcess(PEPROCESS NewProcess)
    {
        PKTHREAD Thread = KeGetCurrentThread();

        PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98);

        if (*(PEPROCESS*)(uintptr_t(ApcState) + 0x20) == NewProcess)
            return;

        if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) != 0))
        {
            KeBugCheck(INVALID_PROCESS_ATTACH_ATTEMPT);
            return;
        }

        MoveApcState(ApcState, *(PKAPC_STATE*)(uintptr_t(Thread) + 0x258));

        InitializeListHead(&ApcState->ApcListHead[KernelMode]);
        InitializeListHead(&ApcState->ApcListHead[UserMode]);

        OldProcess = *(uintptr_t*)(uintptr_t(ApcState) + 0x20);

        *(PEPROCESS*)(uintptr_t(ApcState) + 0x20) = NewProcess;
        *(UCHAR*)(uintptr_t(ApcState) + 0x28) = 0;
        *(UCHAR*)(uintptr_t(ApcState) + 0x29) = 0;
        *(UCHAR*)(uintptr_t(ApcState) + 0x2a) = 0;

        *(UCHAR*)(uintptr_t(Thread) + 0x24a) = 1;
        CR3 = utils::get_process_cr3(NewProcess);
        if (CR3 != NULL)
            __writecr3(CR3);
    }

    void DetachProcess()
    {
        PKTHREAD Thread = KeGetCurrentThread();
        PKAPC_STATE ApcState = *(PKAPC_STATE*)(uintptr_t(Thread) + 0x98);

        if ((*(UCHAR*)(uintptr_t(Thread) + 0x24a) == 0))
            return;

        if ((*(UCHAR*)(uintptr_t(ApcState) + 0x28)) ||
            !(IsListEmpty(&ApcState->ApcListHead[KernelMode])) ||
            !(IsListEmpty(&ApcState->ApcListHead[UserMode])))
        {
            KeBugCheck(INVALID_PROCESS_DETACH_ATTEMPT);
        }

        MoveApcState(*(PKAPC_STATE*)(uintptr_t(Thread) + 0x258), ApcState);

        if (OldProcess)
            *(uintptr_t*)(uintptr_t(ApcState) + 0x20) = OldProcess;

        *(PEPROCESS*)(*(uintptr_t*)(uintptr_t(Thread) + 0x258) + 0x20) = 0;

        *(UCHAR*)(uintptr_t(Thread) + 0x24a) = 0;
       
        __writecr3(CR3);

        if (!(IsListEmpty(&ApcState->ApcListHead[KernelMode])))
        {
            *(UCHAR*)(uint64_t(ApcState) + 0x29) = 1;
        }

        RemoveEntryList(&ApcState->ApcListHead[KernelMode]);

        OldProcess = 0;
    }
#define to_lower(c_char) ((c_char >= 'A' && c_char <= 'Z') ? (c_char + 32) : c_char)

    template <typename str_type, typename str_type_2>
    __forceinline bool crt_strcmp(str_type str, str_type_2 in_str, bool two)
    {
        if (!str || !in_str)
            return false;

        wchar_t c1, c2;
        do
        {
            c1 = *str++; c2 = *in_str++;
            c1 = to_lower(c1); c2 = to_lower(c2);

            if (!c1 && (two ? !c2 : 1))
                return true;

        } while (c1 == c2);

        return false;
    }
    PVOID get_process_peb(HANDLE pid)
    {
        if (!pid)
            return 0;

        PVOID peb_address = 0;
        PEPROCESS process = NULL;
        utils::CustomPsGetPEProcess((ULONGLONG)pid,&process);

        if (!process)
            return 0;
            PPEB peb = PsGetProcessPeb(process);
            if (peb != nullptr)
                peb_address = (PVOID)peb;
        return peb_address;
    }
  
    NTSTATUS get_process_module_information(HANDLE pid, LPCWSTR ModuleNameIn, PVOID* out_base, PVOID* out_peb, PVOID* entry_point, PVOID* out_size)
    {
        if (!pid)
            return STATUS_UNSUCCESSFUL;

        NTSTATUS status;
        SIZE_T s_read = 0;

        PEPROCESS process = NULL;
        utils::CustomPsGetPEProcess((ULONGLONG)pid, &process);
        if (!process)
            return STATUS_UNSUCCESSFUL;

        PVOID peb_address = get_process_peb(pid);
        if (!peb_address)
        {
            //DbgPrintEx(0, 0, "Failed Retrieving PEB \n");
            return STATUS_UNSUCCESSFUL;
        }
           
        *out_peb = peb_address;
        PEB peb_process = { 0 };
        status = utils::readprocessmemory(process,peb_address, &peb_process, sizeof(PEB), &s_read);
        //DbgPrintEx(0, 0, "PEB Found: %p \n",(peb_process));
        if (!NT_SUCCESS(status))
            return status;

        PEB_LDR_DATA peb_ldr_data = { 0 };

        status = utils::readprocessmemory(process,(PVOID)(peb_process.Ldr), & peb_ldr_data, sizeof(PEB_LDR_DATA), & s_read);
        //DbgPrintEx(0, 0, "PEB LDR Found: %p \n", (PVOID)(peb_process.Ldr));
        if (!NT_SUCCESS(status))
            return status;

        LIST_ENTRY* ldr_list_head = (LIST_ENTRY*)peb_ldr_data.InLoadOrderModuleList.Flink;
        LIST_ENTRY* ldr_current_node = peb_ldr_data.InLoadOrderModuleList.Flink;
        do
        {
            LDR_DATA_TABLE_ENTRY lst_entry = { 0 };
            status = utils::readprocessmemory(process, (PVOID)ldr_current_node, & lst_entry, sizeof(LDR_DATA_TABLE_ENTRY), & s_read);
            //DbgPrintEx(0, 0, "LDR Node Found: %p \n", (PVOID)(ldr_current_node));

            if (!NT_SUCCESS(status))
                return status;

            ldr_current_node = lst_entry.InLoadOrderModuleList.Flink;
            if (lst_entry.BaseDllName.Length > 0)
            {
                WCHAR sz_base_dll_name[MAX_PATH] = { 0 };
                status = utils::readprocessmemory(process, (PVOID)lst_entry.BaseDllName.Buffer, & sz_base_dll_name, lst_entry.BaseDllName.Length, & s_read);
                //DbgPrintEx(0, 0, "Module Name : %S \n", sz_base_dll_name);
                //DbgPrintEx(0, 0, "Module Base Address: %p \n", lst_entry.DllBase);
                if (!NT_SUCCESS(status))
                    return status;
   
                if (crt_strcmp(ModuleNameIn, sz_base_dll_name,true) )
                {
                    if (lst_entry.DllBase != 0 && lst_entry.SizeOfImage != 0)
                    {
                        //DbgPrintEx(0, 0, "Module Found X : %p \n", lst_entry.DllBase);
                        *out_base = lst_entry.DllBase;
                        *out_size = (PVOID)lst_entry.SizeOfImage;
                        *entry_point = lst_entry.EntryPoint;
                        break;
                    }
                }
            }

        } while (ldr_list_head != ldr_current_node);
        
        return STATUS_SUCCESS;
    }
}