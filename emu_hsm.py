#!/usr/bin/env python
#encoding=utf-8
"""
（HR/HS）   读密码机信息
（AG/AH）   获取授权
（AC/AD）   取消授权
（AM/AN）   修改口令
（1A/1B）   输入一个密钥，用MK加密输出
（1C/1D）   生成随机密钥，并用MK加密输出
（GY/GZ）   用密的成份合成工作密钥
（1E/1F）   在MK及KEK加密的密钥之间的转换
（2A/2B）   存储一个MK加密的密钥至指定的索引位置
（2C/2D）   读取一个指定的索引的密钥
（3A/3B）   生成密钥的校验值
（3C/3D）   检查一个指定索引号的密钥状态
（RA/RB）   由密码机产生一个随机数
（60/61）   加密一个PIN
（62/63）   转换PIN从一个区域到另一个区域
（68/69）   解密一个PIN
（80/81）   产生MAC
（82/83）   验证MAC
"""
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
        k=triple_des(self.HSM['lmk'])
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
                'keys':{},\
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
