# XNU Kernel Fuzzer
A fuzzer for Apple's iOS (Darwin) Operating System.

The fuzzer talks to several endpoints accessible from within the sandbox and can attack both userland and kernelspace interfaces.

The fuzzer is written in C, Objective-C and inline assembly.

## Userland
- TODO

## Kernelspace
- System calls
- MACH (MUCK) traps
- IOKit and it's children (Kexts and drivers)

## Debugging functionality
- Logs to either Xcode or an in-app view
- Logs processor registers in real-time

# Credits
- Jake James (Mach-O parser for the kernelcache)
- Willem Hengeveld (lzss decompression algorithm)
- OSXFuzz (generic fuzzing functionality)
- Apple Inc. (private headers and frameworks, they might be licensed)
- liblorgnette
- Capstone
