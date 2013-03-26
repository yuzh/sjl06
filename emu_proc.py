import cPickle
from pyDes import *
from binascii import *

class Hsm:
    def __init__(self,fname):
        self.load(fname)
        self.FuncMap={\
            'HR':self.HR_handler,\
        }

    def handle(data):
        return self.FuncMap.get(data[:2])(data)

    def HR_handler(data):
        k=triple_des(self.HSM['lmk']
        result='HS00%s%s'%(hexlify(k.encrypt('\x00'*8)).upper(),\
            'SJL06E HOST SECURITY MODULE: SOFTWARE VERSION 7.4.'\
        )
        return result


    def load(self,fname):
        try:
            self.HSM=cPickle.load(open(fname))
        except IOError:
            self.HSM={\
                'lmk':'',\
                'keys':['']*4096\
                }

    def save(self,fname):
        try:
            self.HSM=cPickle.load(open(fname,'w'))
        except IOError:
            print('save hsm to %s failed!'%fname)

    def getkey(self,i):
        return self.HSM['keys'][i]

    def setkey(self,i,v):
        self.HSM['keys'][i]=v
