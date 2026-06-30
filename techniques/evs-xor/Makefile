CC      = x86_64-w64-mingw32-gcc
PY      = python3
CFLAGS  = -O2 -Wall -Wextra \
           -Iinclude \
           -fno-asynchronous-unwind-tables \
           -fno-ident \
           -fno-stack-protector

SRC     = src/evs.c src/demo.c
OBJ     = $(patsubst src/%.c, build/%.o, $(SRC))
TARGET  = build/demo.exe
HEADER  = include/evs_strings.h

all: $(HEADER) build $(TARGET)

$(HEADER): strings.txt gen_evs.py
	$(PY) gen_evs.py strings.txt -o $(HEADER)

build:
	mkdir -p build

build/%.o: src/%.c $(HEADER)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@

# Rebuild with a new random key
rekey:
	rm -f $(HEADER)
	$(MAKE)

clean:
	rm -rf build $(HEADER)

.PHONY: all rekey clean
