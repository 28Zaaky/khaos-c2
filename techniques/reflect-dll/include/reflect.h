#pragma once
#include <windows.h>

// Exported entry point for the reflective DLL.
// lpParameter is the raw image base in the target process.
ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter);
