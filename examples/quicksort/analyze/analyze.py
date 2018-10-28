#!/usr/bin/env python
from stat import S_ISREG, ST_CTIME, ST_MODE
import os, sys, time
import operator
import matplotlib.pyplot as plt
import numpy as np



def get_files(dirname):
    # path to the directory (relative or absolute)
    dirpath = dirname

    # get all entries in the directory w/ stats
    entries = (os.path.join(dirpath, fn) for fn in os.listdir(dirpath))
    entries = ((os.stat(path), path) for path in entries)
    
    # leave only regular files, insert creation date
    entries = ((stat.st_mtime, path)
               for stat, path in entries if S_ISREG(stat[ST_MODE]))
    #NOTE: on Windows `ST_CTIME` is a creation date 
    #  but on Unix it could be something else
    #NOTE: use `ST_MTIME` to sort by a modification date
    
    files = []
    for cdate, path in sorted(entries):
        files.append([cdate, os.path.abspath(path)])
    
    # sorted_files = sorted(files, key=operator.itemgetter(0))
    results = []
    tzero = files[0][0]
    
    for t, f in files:
        results.append([t-tzero, f])
    results.sort()
    return results

def get_num_instructions():
    lines = open("out.file","r")
    for l in lines:
        if "I   refs:" in l:
            return int(l.rstrip().split(":")[1].replace(',',''))

def exec_valgrind(files, tool):
    
    exec_stat = []
    for t, f in files:
        # print t, f
        valgrind_cmd = "valgrind --tool=cachegrind --cachegrind-out-file=/dev/null ./driver "+ f +" >> out.file 2>&1"
        print valgrind_cmd
        r = os.system(valgrind_cmd)
        if( r != 0):
            print "can not run valgrind"
            sys.exit(-1)

        instrs = get_num_instructions()
        r = os.system("rm out.file")
        if( r != 0):
            print "can not remove out.file"
            sys.exit(-1)
        
        exec_stat.append([t, f, instrs])
    
    return exec_stat

def process_info(exec_stats):
    # sorted( exec_stats, key=operator.itemgetter(0))
    # print exec_stats

    # return [[], []]
    info_map = {}
    maxsofar = 0
    for i in range (0, len(exec_stats)):
        [t, f, instrs] = exec_stats[i]
        maxsofar = max(instrs, maxsofar) 
        info_map[t] = maxsofar
    # print xdata
    # print ydata
    xdata = sorted(info_map.keys())
    ydata = [info_map[t] for t in xdata]

    return [xdata, ydata]

def read_dir(path):
    subdirs = [x[0] for x in os.walk(path)]
    subdirs.remove(path)
    # print subdirs
    result = []

    for sdir in subdirs:
        result.append(get_files(sdir))

    # return sorted(result, key=operator.itemgetter(0))
    return result

def dump_data_tofile(X, Y, TOOL, run):
    f = open(TOOL+"_run"+str(run)+".data", "w")
    assert(len(X) == len(Y))

    for i in range(0, len(X)):
        f.write(str(X[i])+","+str(Y[i])+"\n")

    f.close()

DATA = []

r = os.system("make")
if(r!=0):
    print "make failed"
    sys.exit(-1)


for t in ["x", "slow", "perf"]:
    tool = t
    xdir_files = read_dir("./inputs_"+tool)
    # print xdir_files
    # sys.exit()
    # for t, f in xdir_files:
        # print t, f
    for i in range(0, len(xdir_files)):
        xdir_instr_counts = exec_valgrind(xdir_files[i], tool)
        [xdata, ydata] = process_info(xdir_instr_counts)

        dump_data_tofile(xdata, ydata, tool, i)

sys.exit()
tool = "slow"
xdir_files = get_files("./inputs_"+tool)
# print xdir_files
# for t, f in xdir_files:
    # print t, f
xdir_instr_counts = exec_valgrind(xdir_files, tool)
[xdata, ydata] = process_info(xdir_instr_counts)
# plot_graph(xdata, ydata, "toolX")
DATA.append([xdata, ydata, tool])

tool = "perf"
xdir_files = get_files("./inputs_"+tool)
# print xdir_files
# for t, f in xdir_files:
    # print t, f
xdir_instr_counts = exec_valgrind(xdir_files, tool)
[xdata, ydata] = process_info(xdir_instr_counts)
# plot_graph(xdata, ydata, "toolX")
DATA.append([xdata, ydata, tool])



# plot_graph(DATA)
