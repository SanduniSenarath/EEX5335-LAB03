# EEX5335-LAB03
Memory Management Simulator - C Language


## Files
- memsim.c       : C source code for the simulator
- addresses.txt  : sample input addresses (one per line prefixed with 'R ')
- README.md

## Build
gcc -O2 -std=c11 -o memsim memsim.c

## Run
# Run reading addresses from file:
./memsim addresses.txt

# Verbose per-access info:
./memsim addresses.txt -v
