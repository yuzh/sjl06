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

2013/4/15 完成2C,3A  humx
"""
import cPickle
import pyDes
import binascii as BA
import struct
import random
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
        print "the lmk is ",BA.hexlify(self.HSM['lmk'])
        k=pyDes.triple_des(self.HSM['lmk'])
        result='HS00%s%s'%(BA.hexlify(k.encrypt('\x00'*8)).upper(),\
            'SJL06E HOST SECURITY MODULE: SOFTWARE VERSION 7.4.'\
        )
        return result

    def handle_1E(self,data):#待完成
        """
        （1E/1F）   在MK及KEK加密的密钥之间的转换
        输入指令：2+1+1+(1A+3H)/（16/32/48）+1+16/32/48+4（可选）
            2:'1E'
            1:'1'->从MK加密到KEK加密(输入KEK索引) '2'->从KEK加密到MK加密（输入MK加密KEK密钥）
            1:1->64bit,2->128bit,3->192bit
            (1A+3H)/（16/32/48）：(1A+3H)->KEK索引：K+3N （16/32/48）->由MK加密的密钥
            1：WK单倍长 1->64bit,2->128bit,3->192bit
            16/32/48：MK或KEK加密下的密文
            4（可选）：如果该字段存在，转换后的密钥保存至该索引号中  如‘K003’

        输出结果：2+2+16/32/48+16
            2:"1F"
            2:错误代码，00表示正确
            16/32/48:转换后KEK或MK加密下的WK
            16:WK校验值
        """
        #待完成

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
        print '2A:cipher:',binascii.hexlify(cipher)
        if len(cipher)!=int(keylen)*8:
            return '2B22' #密钥长度与使用模式不符
        k=pyDes.triple_des(self.HSM['lmk'])
        clear=k.decrypt(cipher)
        print '2A:clear:',binascii.hexlify(clear)
        self.setkey(keyindex,clear)

        if keylen=='1':
            wk=pyDes.des(clear)
        else:
            wk=pyDes.triple_des(clear)
        check=wk.encrypt('\x00'*8)
        result='2B00'+BA.hexlify(check).upper()
        return result

    def handle_2C(self,data):
        """
        （2C/2D）   读取一个指定的索引的密钥
        输入指令：2+4
            2:"2A"
            4:"K"+3位16进制索引号(密钥在密码机中要存放的位置（如：K001）)
           
        输出结果：2+2+1+16/32/48+16
            2:"2D"
            2:错误代码，00表示正确
            1:1->64bit,2->128bit,3->192bit
            16/32/48:用主密钥加密的工作密钥密文
            16:单、双、三倍长密钥加密64比特 0的结果。
        """
        code,hexindex=struct.unpack('3s3s',data[:6])
        if code!='2CK':
            return '2D60' #无此命令
        try:
            keyindex=int(hexindex,16)#取得密钥索引
            if keyindex<1 or keyindex>4096:
                raise ValueError
        except ValueError:
            return '2D33' #密钥索引错
        
        clear=self.getkey(keyindex)#取出密钥
        if not clear:
            teturn '2D02' # 工作密钥不存在
        print '2C:clear:',BA.hexlify(clear)
        k=pyDes.triple_des(self.HSM['lmk'])#使用MK加密密钥
        cipher = k.encrypt(clear)
        print '2C:cipher:',BA.hexlify(cipher)
        if len(cipher)%8!=0:#生成密钥长度
            return '2D22'#密钥长度与使用模式不符
        keylen='0'
        if len(cipher)==8:
            keylen='1'
        if len(cipher)==16:
            keylen='2'
        if len(cipher)==24:
            keylen='3'

        if keylen=='0':
            return '2D22'#密钥长度与使用模式不符
        if keylen=='1':#生成校验码
            wk=pyDes.des(clear)
        else:
            wk=pyDes.triple_des(clear)
        check=wk.encrypt('\x00'*8)

        result='2D00'+keylen+BA.hexlify(cipher).upper()+BA.hexlify(check).upper()
        return result

    def handle_3A(self,data):
        """
        （3A/3B）   生成密钥的校验值
        输入指令：2+1+（1A+3H）/16/32/48
            2:"3A"
            1:1->64bit,2->128bit,3->192bit
            4:"K"+3位16进制索引号(密钥在密码机中要存放的位置（如：K001）) 16/32/48:用主密钥加密的工作密钥密文
        输出结果：2+2+16
            2:‘3B’
            2:错误代码，00表示正确
            16:单、双、三倍长密钥加密64比特 0的结果。
        """   
        code,keylen,flagindex=struct.unpack('2s1s1s',data[:4])
        if code!='3A':
            return '3B60' #无此命令
        if keylen not in '123':
            return '3B22' #密钥长度与使用模式不符
        if flagindex=='K':#输入索引
            temp1,temp2 = struct.unpack('2s1s',data[4:7])
            hexindex=temp1+temp2
            print '3A  hexindex:',hexindex
            try:
                keyindex=int(hexindex,16)
                if keyindex<1 or keyindex>4096:
                    raise ValueError
            except ValueError:
                return '3B33' #密钥索引错
            clear=self.getkey(keyindex)#取出密钥
            print '3A:clear:',binascii.hexlify(clear)
            if len(clear)!=int(keylen)*8:
                return '3B22' #密钥长度与使用模式不符

            if keylen=='1':#生成校验码
                wk=pyDes.des(clear)
            else:
                wk=pyDes.triple_des(clear)
            check=wk.encrypt('\x00'*8)
            result='3B00'+binascii.hexlify(check).upper()     
        else:#输入MK加密的密钥
            cipher=binascii.unhexlify(data[3:])
            print '3A:cipher:',binascii.hexlify(cipher)
            if len(cipher)!=int(keylen)*8:
                return '3B22' #密钥长度与使用模式不符
            k=pyDes.triple_des(self.HSM['lmk'])
            clear=k.decrypt(cipher)#解密成明文
            print '3A:clear:',binascii.hexlify(clear)

            if keylen=='1':
                wk=pyDes.des(clear)
            else:
                wk=pyDes.triple_des(clear)
            check=wk.encrypt('\x00'*8)
            result='2B00'+binascii.hexlify(check).upper()
        return result            

    def handle_60(self,data):
        """
         （60/61）   加密一个PIN
        输入指令：2+1+（1A+3H）/16H/32H/48H+2+12+12/18
            2:60
            1:1->64bit,2->128bit,3->192bit
            4:"K"+3位16进制索引号(密钥在密码机中要存放的位置（如：K001）) 16/32/48:用主密钥加密的工作密钥密文
            2:pin块格式 01~06
            12:pin明文要加密的PIN 明文,不足12位填充F。如123456FFFFF
            12/18:账号 12->PIN格式为‘01’ 18->PIN格式为‘04’ 其它PIN格式无此域

        输出结果：2+2+16
            2:61
            2：错误代码，00为正确
            16：加密后的pin模块
        """
        code,keylen,flagindex = struct.unpack('2s1s1s',data[:4])
        if code != '60':
            return '6160'
        if keylen not in '123':
            return '2B22' #密钥长度与使用模式不符
        if flagindex == 'K':#输入密钥索引
            currentend = 7
            #temp1,temp2 = struct.unpack('2s1s',data[4:7])
            hexindex = data[4:7]
            print '60  hexindex:',hexindex
            try:
                keyindex=int(hexindex,16)
                if keyindex<1 or keyindex>4096:
                    raise ValueError
            except ValueError:
                return '6133' #密钥索引错
            clear=self.getkey(keyindex)#取出密钥
            print '3A:clear:',binascii.hexlify(clear)
            if len(clear)!=int(keylen)*8:
                return '6122' #密钥长度与使用模式不符
        else:#输入加密的密钥
            currentend=3+keylen*16
            cipher = binascii.unhexlify(data[3:currentend])#取出加密后密钥
            print '60 cipher:',binascii.hexlify(cipher)
            k = pyDes.triple_des(self.HSM['lmk'])#加密机主密钥
            clear = k.decrypt(cipher)#解密MK加密密钥
            print '60 clear:',binascii.hexlif(clear)

        pintype0,pintype1 = struct.unpack('1s1s',data[currentend:currentend+2])
        currentend = currentend+2
        if (pintype0!='0') or (pintype1 not in '123456'):
            return '6128'#pin格式错
        pin = data[currentend:currentend+12]
        currentend=currentend+12
        pin = pin.strip('F')

        if pintype1 == '1':#格式为01
            pinlen = len(pin)
            number1 = '0'+str(pinlen)+pin+(16-2-pinlen)*'F'#得到PIN数据块1
            account = data[currentend:]#得到账号
            if len(account) != 12:
                return '6128'#pin格式错
            number2 = '0'*4+account#得到PIN数据块2
            print '60 01 number1:',number1
            print '60 01 number2:',number2
            #生成PIN块
            pinblock = ''.join([chr(ord(x[0])^ord(x[1])) for x in zip(binascii.unhexlify(number1),binascii.unhexlify(number2))])
        if pintype1 == '2':#格式为02
            pinlen = len(pin)
            if pinlen > 6:
                return '6129'#pin检查长度大于实际pin长度
            pin = pin+'0'*(6-pinlen)
            pinblock = str(pinlen)+pin+'987654321'
            pinblock = binascii.unhexlify(pinblock)
        if pintype1 == '3':#格式为03
            pinlen = len(pin)
            pinblock = pin + 'F'*(16-pinlen)
            pinblock = binascii.unhexlify(pinblock)
        if pintype1 == '4':#格式为04
            pinlen = len(pin)
            number1 = '0'+str(pinlen)+pin+(16-2-pinlen)*'F'
            account = data[currentend:]
            if len(account) != 18:
                return '6128'#pin格式错
            number2 = 4*'0'+s[-13:-1]
            print '60 04 number1',number1
            print '60 04 number2',number2
            #生成pin块
            pinblock = ''.join([chr(ord(x[0])^ord(x[1])) for x in zip(binascii.unhexlify(number1),binascii.unhexlify(number2))])
        if pintype1 == '5':
            pinlen = len(pin)
            pinblock = '1'+str(pinlen)+pin
            stemp='0123456789ABCDEF'
            for x in range(0,(16-2-pinlen)):
                pinblock = pinblock+random.choice(stemp)
        if pintype1 == '6':
            pinlen = len(pin)
            pinblock = '0'+str(pinlen)+pin+(16-2-pinlen)*'F'

        if keylen=='1':#生成校验码
            wk=pyDes.des(clear)
        else:
            wk=pyDes.triple_des(clear)
        pinresult=wk.encrypt(binascii.unhexlify(pinblock))
        result = '6100'+binascii.hexlify(pinresult).upper()
        
        

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
    print hsm.handle('2AK00220123456789ABCDEF0123456789ABCDEF')
    print hsm.handle('2AKFFF38A5AE1F81AB8F2DD8A5AE1F81AB8F2DD8A5AE1F81AB8F2DD')
    print hsm.handle('2CK001')
    print hsm.handle('2CK002')
    print hsm.handle('2CKFFF')
    print hsm.handle('3A1K001')
    print hsm.handle('3A2K002')
    print hsm.handle('3A10123456789ABCDEF')
    hsm.save()
