AS=gcc
CFLAGS=-m32 -nostdlib
OBJCOPY=objcopy

all: shell.o shell.bin

SOURCE=shell.S

%.bin: %.o
	$(OBJCOPY) -j .text -O binary $< $@

shell.o: $(SOURCE)
	$(AS) $(CFLAGS) -o $@ $^

clean:
	-rm shell.o shell.bin
