
from capstone import *
import sys
from RopTool import *
import getopt

version = "0.1"
author = "zxq_yx_007@163.com"

def usage():
    print "##################################"
    print "simple ROP search tool for ARM"
    print "version: %s" %(version)
    print "author: %s" %(author)
    print "##################################"
    print ""
    print "usage: %s [-h help] [-d <depth>] [-m <mode>] <binary_file>\n" %(sys.argv[0])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(-1)
    # parse arguments

    depth = 5
    mode = "arm"
    opts, args = getopt.gnu_getopt(sys.argv[1:], "hd:m:")

    for op, value in opts:
        if op == "-d":
            depth = int(value)
        elif op == "-m":
            mode = value
        elif op == "-h":
            usage()
            sys.exit()
    
    filename = args[0]
    R = RopTool(filename)
    R.run(depth, mode)
    
