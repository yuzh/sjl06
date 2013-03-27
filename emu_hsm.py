#!/usr/bin/env python
#encoding=utf-8
"""
（HR/HS）   读密码机信息
#（AG/AH）   获取授权
#（AC/AD）   取消授权
#（AM/AN）   修改口令
#（1A/1B）   输入一个密钥，用MK加密输出
#（1C/1D）   生成随机密钥，并用MK加密输出
#（GY/GZ）   用密的成份合成工作密钥
（1E/1F）   在MK及KEK加密的密钥之间的转换
（2A/2B）   存储一个MK加密的密钥至指定的索引位置
（2C/2D）   读取一个指定的索引的密钥
（3A/3B）   生成密钥的校验值
#（3C/3D）   检查一个指定索引号的密钥状态
#（RA/RB）   由密码机产生一个随机数
（60/61）   加密一个PIN
（62/63）   转换PIN从一个区域到另一个区域
（68/69）   解密一个PIN
（80/81）   产生MAC
（82/83）   验证MAC
"""
import cPickle
import pyDes
import binascii
import struct
class Hsm:
    def __init__(self,fname):
        self.hsmfile=fname
        self.load(fname)
        self.FuncMap={}
        # 查找Hsm类中所有形如handle_XX的函数，注册到函数映射表中
        funcs=[x for x in dir(Hsm) \
            if callable(getattr(self,x)) and x[:7]=='handle_']
        # {'XX':handle_XX}
        for f in funcs:
            self.FuncMap[f[-2:]]=getattr(self,f)

    def handle(self,data):
        return self.FuncMap.get(data[:2])(data)

    def handle_HR(self,data):
        """
        （HR/HS）   读密码机信息
        输入指令：2，"HR"
        输出结果：2+2+16+n
            2:"HS"
            2:错误代码，00表示正确
            16:主密钥加密64bit0的结果
            n:返回密码机程序版本号等信息
        """
        print "the lmk is ",binascii.hexlify(self.HSM['lmk'])
        k=pyDes.triple_des(self.HSM['lmk'])
        result='HS00%s%s'%(binascii.hexlify(k.encrypt('\x00'*8)).upper(),\
            'SJL06E HOST SECURITY MODULE: SOFTWARE VERSION 7.4.'\
        )
        return result

    def handle_2A(self,data):
        """
        （2A/2B）   存储一个MK加密的密钥至指定的索引位置
        输入指令：2+4+1+16/32/48
            2:"2A"
            4:"K"+3位16进制索引号
            1:1->64bit,2->128bit,3->192bit
            16/32/48:由MK加密的密钥
        输出结果：2+2+16
            2:"2B"
            2:错误代码，00表示正确
            16:单、双、三倍长密钥加密64比特 0的结果。
        """
        code,hexindex,keylen=struct.unpack('3s3s1s',data[:7])
        if code!='2AK':
            return '2B60' #无此命令
        try:
            keyindex=int(hexindex,16)
            if keyindex<1 or keyindex>4096:
                raise ValueError
        except ValueError:
            return '2B33' #密钥索引错
        if keylen not in '123':
            return '2B22' #密钥长度与使用模式不符
        
        cipher=binascii.unhexlify(data[7:])
        #print 'cipher:',binascii.hexlify(cipher)
        if len(cipher)!=int(keylen)*8:
            return '2B22' #密钥长度与使用模式不符
        k=pyDes.triple_des(self.HSM['lmk'])
        clear=k.decrypt(cipher)
        #print 'clear:',binascii.hexlify(clear)
        self.setkey(keyindex,clear)

        if keylen=='1':
            wk=pyDes.des(clear)
        else:
            wk=pyDes.triple_des(clear)
        check=wk.encrypt('\x00'*8)
        result='2B00'+binascii.hexlify(check).upper()
        return result


    def load(self,fname):
        try:
            self.HSM=cPickle.load(open(fname))
        except:
            self.HSM={\
                'lmk':'\x11'*24,\
                'password':'FFFFFFFF',\
                'authorized':False,\
                'keys':{},\
                'whitelist':[],\
                }

    def save(self):
        try:
            cPickle.dump(self.HSM,open(self.hsmfile,'w'))
        except IOError:
            print('save hsm to %s failed!'%self.hsmfile)

    def getkey(self,i):
        return self.HSM['keys'].get(i)

    def setkey(self,i,v):
        self.HSM['keys'][i]=v


if __name__=='__main__':
    hsm=Hsm('hsm.dat')
    print hsm.handle('HR')
    print hsm.handle('2AK00110123456789ABCDEF')
    print hsm.handle('2AKFFF18A5AE1F81AB8F2DD')
    hsm.save()
