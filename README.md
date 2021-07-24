# elf2mod

A utility that converts a specially-crafted m68k ELF object into a OS-9/68000 executable file.

# Usage

- Prepare a specially-crafted ELF file
  - See next section for details
- Run elf2mod, like `elf2mod some.elf CDI_SOME.APP`
  - In default, module name become basename without extension of output file, in lower case.
  - In above example, it become `cdi_some`
- Profit!

You can `elf2mod --help` to get descriptions of options.

You need to have OS-9/68000 executable knowledge...

# Specially-crafted ELF file?

- Contains `.text`, `.data` and `.bss` sections
  - Other sections are ignored, including `.text.*`, `.rodata`, etc.
  - You must meld them into above sections (using linker script.)
- `.text` VMA must be at 0 (this can be improved...)
- `.text` must *NOT* contains relocations to .data/.bss, *except* `R_68K_16` (for referencing .data/.bss symbols relative to A6 register)
  - Other relocations are not allowed, ex. `R_68K_32`
- `.data` VMA must be at -0x8000 like
  - No bias are done for `R_68K_16` in `.text` by elf2mod.
  - In other words, -0x8000 bias must be done at ELF file.
- `.data` must *NOT* contains relocations *except* 32bit direct relocations i.e. `R_68K_32`
- `.bss` must be contiguous after `.data` (usually it is.)
- `.bss` must not have CONTENTS (usually it is.)
- Relocation values must be applied but relocation itself must be left
  - in GNU ld, it can be done with `-q`

# Build and install

- Pre-requisite: BFD for m68k-elfos9 is installed. (binutils with `--enable-install-libbfd`)
- Tweak `BFDPATH` in Makefile (if you are not on linux-amd64)
- `make && make install`
  - you can specify DESTDIR= to set install prefix.
	- `make DESTDIR=/usr install` installs elf2mod as `/usr/bin/elf2mod`
- Profit!

# License

MIT
