CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra \
           -Iinclude \
           -fno-asynchronous-unwind-tables \
           -fno-ident \
           -fno-stack-protector
LDFLAGS = -lntdll

SRC_C   = src/indirect_syscall.c src/demo.c
SRC_S   = src/spoof_stub.S
OBJ_C   = $(patsubst src/%.c, build/%.o, $(SRC_C))
OBJ_S   = $(patsubst src/%.S, build/%.o, $(SRC_S))
OBJ     = $(OBJ_C) $(OBJ_S)
TARGET  = build/demo.exe

all: build $(TARGET)

build:
	mkdir -p build

build/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: src/%.S
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

clean:
	rm -rf build

.PHONY: all clean
