#encoding=utf-8
"""
2013/5/17 humx complete
2013/7/8 humx 修改pin命令
"""
import random

class myPin:
    def __init__(self,pin_code='',pin_account='',pin_fmt=''):
        self.pin_code = pin_code
        self.pin_account = pin_account
        self.pin_fmt = pin_fmt;
        self.pin_block = ''
        self.error_code = 0
        self.error_str = ''

    def format(self):
        if self.pin_fmt in ['01','02','03','04','05','06']:
            self.format_fun = getattr(self,"format_%s"%(self.pin_fmt))
            return self.format_fun()
        else:
            raise ValueError("Invalid pin format")

    def de_format(self,pin_fmt,pin_block,pin_account=''):
        if pin_fmt in ['01','02','03','04','05','06']:
            self.de_format_fun = getattr(self,"de_format_%s"%(pin_fmt))
            return self.de_format_fun(pin_block,pin_account)
        else:
            raise ValueError("Invalid pin format")



    def format_01(self):
        block_1 = "0%s%s"%(hex(len(self.pin_code))[2:].upper(),self.pin_code)
        if(len(block_1)>16):
            raise ValueError("Invalid pin length")
        else:
            block_1 += (16-len(block_1))*'F'
        
        len_account = len(self.pin_account)
        if(len_account < 12):
            raise ValueError("Invalid pin account length")

        block_2 = "0000%s"%(self.pin_account[len_account-12:len_account])
        pin_list = map(lambda x:hex(int(block_2[x[0]],16)^int(x[1],16))[2:].upper(),enumerate(block_1))
        pin_block = ''.join(pin_list)

        return pin_block

    def de_format_01(self,pin_block,pin_account):
        len_account = len(pin_account)
        if len_account < 12:
            raise ValueError("Invalid pin account length")
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")

        self.pin_account = pin_account
        block_1 = "0000%s"%(self.pin_account[len_account-12:len_account])
        pin_list = map(lambda x:hex(int(block_1[x[0]],16)^int(x[1],16))[2:].upper(),enumerate(pin_block))
        pin_len = int(pin_list[1],16)
        self.pin_code = ''.join(pin_list[2:2+pin_len])
        return self.pin_code         

    def format_02(self):
        pin_block = "%s%s%s%s"%(hex(len(self.pin_code))[2:].upper(),self.pin_code,(6-len(self.pin_code))*'0',"987654321")
        if(len(pin_block)>16):
            raise ValueError("Invalid pin length")  

        return pin_block
    
    def de_format_02(self,pin_block,pin_account=''):
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")
        pin_len = int(pin_block[0],16)
        self.pin_code = pin_block[1:1+pin_len]
        return self.pin_code
         

    def format_03(self):
        pin_block = "%s%s"%(self.pin_code,(16-len(self.pin_code))*'F')
        if(len(pin_block)>16):
            raise ValueError("Invalid pin length")
        return pin_block

    def de_format_03(self,pin_block,pin_account=''):
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")
        self.pin_code = filter(lambda x:x<'F',pin_block)
        return self.pin_code


    def format_04(self):
        block_1 = "0%s%s"%(hex(len(self.pin_code))[2:].upper(),self.pin_code)
        if(len(block_1)>16):
            raise ValueError("Invalid pin length")
        else:
            block_1 += (16-len(block_1))*'F'

        if(len(self.pin_account) < 12):
            raise ValueError("Invalid pin account length")
       
        block_2 = "0000%s"%(self.pin_account[0:12])
        pin_list = map(lambda x:hex(int(block_2[x[0]],16)^int(x[1],16))[2:].upper(),enumerate(block_1))
        pin_block = ''.join(pin_list)
        return pin_block

    def de_format_04(self,pin_block,pin_account=''):
        len_account = len(pin_account)
        if len_account < 12:
            raise ValueError("Invalid pin account length")
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")
        
        self.pin_account = pin_account
        block_1 = "0000%s"%(self.pin_account[0:12])
        pin_list = map(lambda x:hex(int(block_1[x[0]],16)^int(x[1],16))[2:].upper(),enumerate(pin_block))
        pin_len = int(pin_list[1],16)
        self.pin_code = ''.join(pin_list[2:2+pin_len])
        return self.pin_code         


    def format_05(self):
        random.seed()
        rand_str = ''.join([hex(random.randint(0,15))[2:] for i in range(0,16)]).upper()
        len_pin = len(self.pin_code)
        if len_pin > 12:
            raise ValueError("Invalid pin length")
        
        pin_block = "1%s%s%s"%(hex(len(self.pin_code))[2:].upper(),self.pin_code,rand_str[0:(16-2-len_pin)])
        return pin_block

    def de_format_05(self,pin_block,pin_account=''):
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")
        pin_len = int(pin_block[1],16)
        self.pin_code = pin_block[2:2+pin_len]
        return self.pin_code

        
    def format_06(self):
        len_pin = len(self.pin_code)
        if len_pin > 12:
            raise ValueError("Invalid pin length")
        
        pin_block = "0%s%s%s"%(hex(len(self.pin_code))[2:].upper(),self.pin_code,(16-2-len_pin)*'F')
        return pin_block
    
    def de_format_06(self,pin_block,pin_account=''):
        if len(pin_block) != 16:
            raise ValueError("Invalid pin block length")
        pin_len = int(pin_block[1],16)
        self.pin_code = pin_block[2:2+pin_len]
        return self.pin_code

        




if __name__ == "__main__":
    p1 = myPin('92389','400000123456')
    print p1.format_01()
    
    t = myPin()
    print t.de_format_01(p1.format_01(),'400000123456')

    print p1.format_02()
    print t.de_format_02(p1.format_02())
    print p1.format_03()
    print t.de_format_03(p1.format_03())
    print p1.format_04()
    print t.de_format_04(p1.format_04(),'400000123456')

    p2 = myPin('92389','2283400000123456')
    print p2.format_05()
    print t.de_format_05(p2.format_05())
    print p2.format_06()
    print t.de_format_06(p2.format_06())
    print t.de_format('01',p1.format_01(),'400000123456')


