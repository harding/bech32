from sys import argv
from hashlib import sha256
import segwit_addr

## Make results completely reproducible by using a shachain initialized
## from a seed.  Read seed from CLI parameters so I can easily use all
## CPUs by doing something like:
##   for i in $( seq $( nproc ) ) ; do python3 -u test-len-errors.py $i > results.$i.txt & done
SEED=str(argv[1])

## Print the seed into the log
print('Seed: "{}"'.format(SEED))

## Initialize the program value from our seed
program = sha256(bytes(SEED, 'utf-8')).digest()

iterations=0
while True:
    ## Derive a new (dummy) witness program
    program = sha256(bytes(program)).digest()

    ## Create a v1 segwit address for the program
    addr = segwit_addr.encode('bc1', 1, program)

    ## Save the correct decoding of that address
    correct_decode = test_result = segwit_addr.decode('bc1', addr)
    
    ## Delete one character.  Pieter Wuille implies the mechanism by
    ## which an insertion/deletion error is caught is that they shift all
    ## the subsequent characters in the string by one place, so either type
    ## of error should be sufficient for testing the rate at which errors
    ## are caught.  Deletion is easiest to implement, so we do that.  In the following, we
    ## assume the user doesn't make an error on the hrp but might
    ## accidentally omit any other single character in the 64-character
    ## segwit v1 address with a 32-byte payload.
    for i in range(3, 63):
        mod_addr = addr[:i] + addr[i+1:]
        mod_decode = segwit_addr.decode('bc1', mod_addr)
        if mod_decode != (None, None):
            print("RESULT:", addr, mod_addr)

    ## Quick testing on my laptop suggests that:
    ##   - 1,000 iterations in about 6 seconds (60,000 checks)
    ##   - 1e4 in 60 seconds (6e5 checks)
    ##   - 1e5 in 10 minutes (6e6)
    ##   - 1e6 in 100 minutes (6e7)
    ##   - 1e7 in 17 hours (6e8), >50% chance of detection around here
    iterations += 1
    if iterations % 1e3 == 0:
        ## The character deletion loop checks 60 different variations
        print("Iterations:", iterations * 60, "Last address:", addr)
