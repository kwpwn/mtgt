CC     = x86_64-w64-mingw32-gcc
CFLAGS = -masm=intel -Wall -fno-asynchronous-unwind-tables
INC    = -I.
OBJ    = disable_nic.x64.obj

.PHONY: all clean

all: $(OBJ)

$(OBJ): bof_disable_nic.c beacon.h
	$(CC) $(CFLAGS) $(INC) -c bof_disable_nic.c -o $(OBJ)
	@echo "[+] Build OK: $(OBJ)"

clean:
	rm -f $(OBJ) bof_disable_nic.o
