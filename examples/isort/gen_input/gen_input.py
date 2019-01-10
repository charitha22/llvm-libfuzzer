import os, sys
import struct

def gen_array(N):
    arr = []
    for i in range(0,N):
        arr.append(N-i)

    return arr

# print gen_array(20)
SIZE = 100
fname = "input"+str(SIZE)
f = open(fname, "w")
input_array = gen_array(SIZE)

for n in input_array:
    f.write(chr(n))

# read the result
f = open(fname, "r")
output = []
while 1:
    c = f.read(1)
    if not c:
        break
    # print(ord(c))
    output.append(ord(c))

print output
