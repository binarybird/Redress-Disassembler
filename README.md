# Redress Disassembler
Redress is a cross platform binary disassembler written in Java/JavaFX with [Capstone bindings](https://github.com/aquynh/capstone/tree/master/bindings/java)

MachO 64bit ABI support is in the works. Future plans include ELF and PE ABIs as well as lldb integration. Disassembling compiled text is made possible by the [Capstone project](http://www.capstone-engine.org/) and its Java bindings. Redress also uses [DockFX](https://github.com/RobertBColton/DockFX) for its detachable pane system.

This project is still under heavy development (just started on it). Redress is a project I started because I was bored and wanted to better understand reverse engineering. Feel free to fork and/or contribute (I do need someone on PE and ELF).

Heres a screenshot of the working prototype. It is able to read and decompile basic Mach-O 64bit binaries

![alt text](GUI_PROTO.png "gui prototype")


