#include "commands.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* parse hive prefix and return root HKEY */

static HKEY _hive(const char *keypath, const char **subkey)
{
    static const struct { const char *pfx; HKEY hive; } map[] = {
        {"HKEY_LOCAL_MACHINE\\",  HKEY_LOCAL_MACHINE},
        {"HKLM\\",                HKEY_LOCAL_MACHINE},
        {"HKEY_CURRENT_USER\\",   HKEY_CURRENT_USER},
        {"HKCU\\",                HKEY_CURRENT_USER},
        {"HKEY_USERS\\",          HKEY_USERS},
        {"HKU\\",                 HKEY_USERS},
        {"HKEY_CLASSES_ROOT\\",   HKEY_CLASSES_ROOT},
        {"HKCR\\",                HKEY_CLASSES_ROOT},
        {"HKEY_CURRENT_CONFIG\\", HKEY_CURRENT_CONFIG},
        {"HKCC\\",                HKEY_CURRENT_CONFIG},
    };
    for (int i = 0; i < (int)(sizeof(map)/sizeof(map[0])); i++) {
        size_t len = strlen(map[i].pfx);
        if (_strnicmp(keypath, map[i].pfx, len) == 0) {
            *subkey = keypath + len;
            return map[i].hive;
        }
    }
    *subkey = keypath;
    return NULL;
}

static const char *_type_name(DWORD t)
{
    switch (t) {
        case REG_SZ:          return "REG_SZ";
        case REG_EXPAND_SZ:   return "REG_EXPAND_SZ";
        case REG_MULTI_SZ:    return "REG_MULTI_SZ";
        case REG_DWORD:       return "REG_DWORD";
        case REG_QWORD:       return "REG_QWORD";
        case REG_BINARY:      return "REG_BINARY";
        case REG_NONE:        return "REG_NONE";
        default:              return "REG_UNKNOWN";
    }
}

/* Format a registry value into buf */
static int _fmt_value(const char *name, DWORD type,
                      const BYTE *data, DWORD datalen,
                      char *buf, size_t bufsz)
{
    char val[1024] = {0};

    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ:
        snprintf(val, sizeof(val), "\"%.*s\"", (int)datalen, (const char *)data);
        break;

    case REG_MULTI_SZ: {
    /* NUL-separated list */
        size_t pos = 0;
        const char *s = (const char *)data;
        while (s < (const char *)data + datalen && *s) {
            int n = snprintf(val + pos, sizeof(val) - pos, "%s; ", s);
            if (n > 0) pos += (size_t)n;
            s += strlen(s) + 1;
        }
        break;
    }

    case REG_DWORD:
        if (datalen >= 4) {
            DWORD dw;
            memcpy(&dw, data, 4);
            snprintf(val, sizeof(val), "0x%08lX (%lu)", dw, dw);
        }
        break;

    case REG_QWORD:
        if (datalen >= 8) {
            ULONGLONG qw;
            memcpy(&qw, data, 8);
            snprintf(val, sizeof(val), "0x%016llX", qw);
        }
        break;

    case REG_BINARY: {
        size_t pos = 0;
        for (DWORD i = 0; i < datalen && pos + 3 < sizeof(val); i++) {
            snprintf(val + pos, sizeof(val) - pos, "%02X ", data[i]);
            pos += 3;
        }
        break;
    }

    default:
        snprintf(val, sizeof(val), "<binary %lu bytes>", datalen);
        break;
    }

    return snprintf(buf, bufsz, "  %-30s  %-14s  %s\n",
                    name[0] ? name : "(Default)", _type_name(type), val);
}

/* query one value or enumerate all values in a key */

int cmd_reg_query(const char *keypath, const char *valname,
                  char *output_buf, size_t output_size)
{
    const char *subkey = NULL;
    HKEY        hive   = _hive(keypath, &subkey);
    if (!hive) {
        snprintf(output_buf, output_size,
                 "[reg] unknown hive in: %s\n", keypath);
        return -1;
    }

    HKEY hk;
    LONG rc = RegOpenKeyExA(hive, subkey, 0, KEY_READ, &hk);
    if (rc != ERROR_SUCCESS) {
        snprintf(output_buf, output_size,
                 "[reg] RegOpenKeyEx failed: %ld\n", rc);
        return -1;
    }

    size_t pos = 0;
    int n = snprintf(output_buf + pos, output_size - pos,
                     "%s\n", keypath);
    if (n > 0) pos += (size_t)n;

    if (valname && valname[0]) {
        /* query single value */
        BYTE  buf[4096];
        DWORD datalen = sizeof(buf);
        DWORD type    = 0;
        rc = RegQueryValueExA(hk, valname, NULL, &type, buf, &datalen);
        if (rc == ERROR_SUCCESS) {
            char line[2048];
            _fmt_value(valname, type, buf, datalen, line, sizeof(line));
            n = snprintf(output_buf + pos, output_size - pos, "%s", line);
            if (n > 0) pos += (size_t)n;
        } else {
            n = snprintf(output_buf + pos, output_size - pos,
                         "  [not found: %s]\n", valname);
            if (n > 0) pos += (size_t)n;
        }
    } else {
        /* enumerate all values */
        DWORD idx = 0;
        for (;;) {
            char  name[256];
            BYTE  data[4096];
            DWORD namesz = sizeof(name);
            DWORD datasz = sizeof(data);
            DWORD type   = 0;
            rc = RegEnumValueA(hk, idx++, name, &namesz, NULL,
                               &type, data, &datasz);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS)       break;

            char line[2048];
            _fmt_value(name, type, data, datasz, line, sizeof(line));
            n = snprintf(output_buf + pos, output_size - pos, "%s", line);
            if (n > 0 && (size_t)n < output_size - pos)
                pos += (size_t)n;
            else
                break;
        }
        if (idx == 1) {
            n = snprintf(output_buf + pos, output_size - pos,
                         "  (no values)\n");
            if (n > 0) pos += (size_t)n;
        }
    }

    RegCloseKey(hk);
    return 0;
}

/* set a registry value */

int cmd_reg_set(const char *keypath, const char *valname,
                const char *type_str, const char *value,
                char *output_buf, size_t output_size)
{
    const char *subkey = NULL;
    HKEY        hive   = _hive(keypath, &subkey);
    if (!hive) {
        snprintf(output_buf, output_size,
                 "[reg] unknown hive in: %s\n", keypath);
        return -1;
    }

    /* resolve type string */
    DWORD type = REG_SZ;
    if (_stricmp(type_str, "REG_DWORD") == 0 || _stricmp(type_str, "dword") == 0)
        type = REG_DWORD;
    else if (_stricmp(type_str, "REG_BINARY") == 0 || _stricmp(type_str, "binary") == 0)
        type = REG_BINARY;
    else if (_stricmp(type_str, "REG_EXPAND_SZ") == 0 || _stricmp(type_str, "expand_sz") == 0)
        type = REG_EXPAND_SZ;
    else if (_stricmp(type_str, "REG_MULTI_SZ") == 0 || _stricmp(type_str, "multi_sz") == 0)
        type = REG_MULTI_SZ;
    /* else default REG_SZ */

    HKEY hk;
    LONG rc = RegCreateKeyExA(hive, subkey, 0, NULL,
                              REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                              NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS) {
        snprintf(output_buf, output_size,
                 "[reg] create failed: %ld\n", rc);
        return -1;
    }

    LONG set_rc = ERROR_SUCCESS;

    switch (type) {
    case REG_DWORD: {
        DWORD dw = (DWORD)strtoul(value, NULL, 0);
        set_rc = RegSetValueExA(hk, valname, 0, REG_DWORD,
                                (const BYTE *)&dw, sizeof(DWORD));
        break;
    }
    case REG_BINARY: {
        /* parse hex string to bytes */
        size_t vlen = strlen(value);
        BYTE  *bin  = (BYTE *)malloc((vlen / 2) + 1);
        if (!bin) { RegCloseKey(hk); return -1; }
        size_t blen = 0;
        for (size_t i = 0; i + 1 < vlen; i += 2) {
            char hx[3] = {value[i], value[i+1], '\0'};
            bin[blen++] = (BYTE)strtoul(hx, NULL, 16);
        }
        set_rc = RegSetValueExA(hk, valname, 0, REG_BINARY, bin, (DWORD)blen);
        free(bin);
        break;
    }
    default: /* REG_SZ, REG_EXPAND_SZ */
        set_rc = RegSetValueExA(hk, valname, 0, type,
                                (const BYTE *)value,
                                (DWORD)(strlen(value) + 1));
        break;
    }

    RegCloseKey(hk);

    if (set_rc == ERROR_SUCCESS) {
        snprintf(output_buf, output_size,
                 "[reg] set %s\\%s  (%s) = %s\n",
                 keypath, valname, type_str, value);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[reg] set failed: %ld\n", set_rc);
    return -1;
}

/* delete a registry key or value */

int cmd_reg_delete(const char *keypath, const char *valname,
                   char *output_buf, size_t output_size)
{
    const char *subkey = NULL;
    HKEY        hive   = _hive(keypath, &subkey);
    if (!hive) {
        snprintf(output_buf, output_size,
                 "[reg] unknown hive in: %s\n", keypath);
        return -1;
    }

    LONG rc;

    if (!valname || !valname[0]) {
        /* delete the key itself */
        rc = RegDeleteKeyA(hive, subkey);
        if (rc == ERROR_SUCCESS) {
            snprintf(output_buf, output_size,
                     "[reg] deleted key: %s\n", keypath);
            return 0;
        }
        snprintf(output_buf, output_size,
                 "[reg] RegDeleteKey failed: %ld\n", rc);
        return -1;
    }

    /* delete specific value */
    HKEY hk;
    rc = RegOpenKeyExA(hive, subkey, 0, KEY_SET_VALUE, &hk);
    if (rc != ERROR_SUCCESS) {
        snprintf(output_buf, output_size,
                 "[reg] RegOpenKeyEx failed: %ld\n", rc);
        return -1;
    }

    rc = RegDeleteValueA(hk, valname);
    RegCloseKey(hk);

    if (rc == ERROR_SUCCESS) {
        snprintf(output_buf, output_size,
                 "[reg] deleted value: %s \\ %s\n", keypath, valname);
        return 0;
    }
    snprintf(output_buf, output_size,
             "[reg] RegDeleteValue failed: %ld\n", rc);
    return -1;
}
