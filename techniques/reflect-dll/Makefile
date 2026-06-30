CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra \
           -Iinclude \
           -fno-asynchronous-unwind-tables \
           -fno-ident \
           -fno-stack-protector
LDFLAGS = -Wl,--file-alignment,0x1000

DLL_SRC = src/reflect.c src/example_dll.c
EXE_SRC = examples/loader.c
DLL_OUT = build/example.dll
EXE_OUT = build/loader.exe

all: build $(DLL_OUT) $(EXE_OUT)

build:
	mkdir -p build

$(DLL_OUT): $(DLL_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^

$(EXE_OUT): $(EXE_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -rf build

.PHONY: all clean
