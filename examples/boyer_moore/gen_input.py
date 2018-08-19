import sys
size = int(sys.argv[1])

data = []
for i in range(0,size-1):
    data.append(98)

data.append(99)

fname = "input"+str(size)
f = open(fname,"w")

for d in data:
    f.write(chr(d))

print data
