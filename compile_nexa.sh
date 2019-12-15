#! /bin/bash --
set -ex
gcc -m32 -static -fno-pic -fno-use-linker-plugin -fno-stack-protector -fno-ident -fno-builtin -Os -march=i686 -W -Wall -Werror -fomit-frame-pointer -falign-functions=1 -mpreferred-stack-boundary=2 -falign-jumps=1 -falign-loops=1 -ffreestanding -nostdlib -lgcc -Wl,--defsym=_start=137 -Wl,--build-id=none -fno-unwind-tables -fno-asynchronous-unwind-tables -o nexa32.elf nexa.c
gcc -m64 -static -fno-pic -fno-use-linker-plugin -fno-stack-protector -fno-ident -fno-builtin -Os -W -Wall -Werror -fomit-frame-pointer -falign-functions=1 -mpreferred-stack-boundary=4 -falign-jumps=1 -falign-loops=1 -ffreestanding -nostdlib -lgcc -Wl,--defsym=_start=137 -Wl,--build-id=none -fno-unwind-tables -fno-asynchronous-unwind-tables -o nexa64.elf nexa.c
: compile_nexa.sh OK.

