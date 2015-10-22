
from capstone import *
from gadget import *
from loaders.elf import *
from struct import unpack

class RopTool:
    def __init__(self, path):
        self.gadgets = []
        self.__binary = None
        with open(path, mode='rb') as file:
            self.__binary = file.read()
        file.close()
        self.elf = ELF(self.__binary)
        
    def run(self, depth = 5, mode = "arm"):
        sections = self.elf.getExecSections()
        g = Gadget(self.elf, depth, mode)
        for s in sections:
            self.gadgets.append(g.getROPGadgets(s))

        self.output()

    def output(self):
        for i in self.gadgets:
            for j in i:
                print "0x%x : %s" %(j["vaddr"], j["gadget"])
                #print " @@ ",
                #self.printBytes(j["codes"])

    def printBytes(self, array):
        index = 0
        ret = []
        step = 4
        #print array
        #print len(array)
        while index < len(array):
            if (len(array) - index) >= 4:
                step = 4
                ret += [unpack("<I", array[index:index + step])]
            elif (len(array) - index) >= 2:
                step = 2
                ret += [unpack("<H", array[index:index + step])]
            else:
                step = 1
                ret += [unpack("<B", array[index:index + step])]
            index += step

        for i in ret:
            print "0x%x" %(i),
        print ""
                
            

        
