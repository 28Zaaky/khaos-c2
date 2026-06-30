CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -Wextra \
           -Iinclude \
           -fno-asynchronous-unwind-tables \
           -fno-ident \
           -fno-stack-protector
LDFLAGS = -lamsi

SRC     = src/hwbp_evasion.c src/demo.c
OBJ     = $(patsubst src/%.c, build/%.o, $(SRC))
TARGET  = build/demo.exe

all: build $(TARGET)

build:
	mkdir -p build

build/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

clean:
	rm -rf build

.PHONY: all clean
