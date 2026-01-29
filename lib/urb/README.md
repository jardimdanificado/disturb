# urb
urb is a minimal footprint bytecode virtual machine;

# urbpack
urbake collect all .c, .papagaio and .urb files in the current path and generates a .c file ready to compile.

the .c files is where we store our opcodes, all compatible functions will be added as opcode.

the .papagaio files is where we store our rules, you might want to know https://github.com/jardimdanificado/papagaio

the .urb is the source code, is recommended to have only one .urb file since the order is not guaranteed.