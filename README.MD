A fork of https://github.com/jdinunzio/forthos

The original repo won't build with Python 3.x, because of forth2s.py that depends on a Python 2.x module.

This repo attempt to fix that. Tested only on MacOS, btw. Please install i386-elf-gcc:
https://github.com/nativeos/homebrew-i386-elf-toolchain

Kernel is buildable, but not the final .img yet, because that depends on losetup which is Linux-specific.
No idea how to port that into macOS...
