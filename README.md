# BinaryProject3

### Dependencies

Binary Analysis Toolkit: pip install angr

## Steps
1. Compiling C Code into a Binary.
2. Preprocess cpp where all the #include, #define, and #ifdef macros are expanded and resolved.
3. Where the preprocessed code is converted into assembly (translated into raw machine code).


### Compiling C Code into a Binary
For Mac:    clang hello_world.c -o hello_world

For Windows:    gcc hello_world.c -o hello_world

