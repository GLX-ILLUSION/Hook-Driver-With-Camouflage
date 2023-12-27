#pragma once


#include <ntifs.h>
#include <ntstrsafe.h>

NTSTATUS DelDriverFile(PUNICODE_STRING pUsDriverPath);