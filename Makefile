CC=gcc
CFLAGS=-Wextra -Wall -pedantic -fvisibility=hidden -Wconversion -Wcast-align -Wmissing-field-initializers -Wshadow -Wswitch-enum -Wmissing-prototypes -Wformat=2 -fwrapv --param ssp-buffer-size=4 -fstack-protector-strong -fzero-call-used-regs=used-gpr -ffat-lto-objects -Wframe-larger-than=2048 -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -fPIE -fpic -Os

debug:clean
	$(CC) $(CFLAGS) -g -o xdrbg xdrbg.c
stable:clean
	$(CC) $(CFLAGS) -o xdrbg xdrbg.c
all:stable
clean:
	rm -vfr *~ xdrbg
