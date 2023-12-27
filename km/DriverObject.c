#include"Head.h"




PDRIVER_OBJECT FindNotDeviceDriver() {
	PUCHAR DriverObjectByte = (PUCHAR)Driver;
	POBJECT_HEADER_NAME_INFO PObjHeaderNameInfo = DriverObjectByte - _OBJECT_HEADER_Body_Offset - sizeof(OBJECT_HEADER_NAME_INFO);
	POBJECT_DIRECTORY PDirectory = PObjHeaderNameInfo->Directory;
	PDRIVER_OBJECT TargetDrvObj = NULL;
	POBJECT_DIRECTORY_ENTRY PSubDirectoryEntry = NULL;
	POBJECT_DIRECTORY_ENTRY PDirectoryEntry = NULL;
	for (int i = 0; i < 37; i++) {
		PDirectoryEntry = PDirectory->HashBuckets[i];
		if (PDirectoryEntry == NULL) {
			continue;
		}
		PSubDirectoryEntry = PDirectoryEntry;
		while (PSubDirectoryEntry != NULL) {
			TargetDrvObj = PSubDirectoryEntry->Object;
			if (TargetDrvObj->DeviceObject == NULL) {
				return TargetDrvObj;
			}
			PSubDirectoryEntry = PSubDirectoryEntry->ChainLink;
		}
	}
	return NULL;
}