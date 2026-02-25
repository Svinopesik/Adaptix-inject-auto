CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded
CFLAGS = -I _include -w -Wno-int-conversion -Wno-incompatible-pointer-types -Os -DBOF -c

all: bof

bof: clean
	@mkdir -p _bin
	@echo '[*] Creating _bin directory'
	@echo '[*] Compiling inject_pid.c (x64)...'
	$(CC64) $(CFLAGS) inject_pid.c -o _bin/inject_sec_auto.x64.o && \
	$(STRIP64) _bin/inject_sec_auto.x64.o && \
	echo '[+] inject_sec_auto.x64.o compiled successfully' || \
	echo '[!] inject_sec_auto.x64.o compilation failed'
	@echo '[*] Compiling inject_pid.c (x86)...'
	$(CC86) $(CFLAGS) inject_pid.c -o _bin/inject_sec_auto.x86.o && \
	$(STRIP86) _bin/inject_sec_auto.x86.o && \
	echo '[+] inject_sec_auto.x86.o compiled successfully' || \
	echo '[!] inject_sec_auto.x86.o compilation failed'

clean:
	@rm -rf _bin
	@echo '[*] Cleaned _bin directory'

.PHONY: all bof clean
