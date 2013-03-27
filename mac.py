#!/usr/bin/env python
import pyDes
ANSI_X99=1
ANSI_X919=2
class mac:
	def __init__(self,key,mode=ANSI_X99,IV='\0'*8):
		self.block_size = 8
		self.setMode(mode)
		self.__padding = ''
		self.__iv = IV
		self.setKey(key)

	def setMode(self,mode):
		if mode not in (ANSI_X99,ANSI_X919):
			raise ValueError("Invalid mac MODE,MODE must be ANSIX99 or ANSIX919")
		self.__mode = mode

	def getMode(self):
		return self.__mode

	def setIV(self,IV):
		self.__iv = IV

	def getIV(self):
		return self.__iv

	def setKey(self,key):
		self.__keysize=len(key)
		#print "key is",key
		#print "len is",len(key)
		if self.getMode()==ANSI_X919:
			if self.__keysize!=16:
				raise ValueError("Invalid key size,ANSIX919 need 16 bytes")
			self.__key1=pyDes.des(key[:8])
			self.__key2=pyDes.des(key[8:])
		if self.getMode()==ANSI_X99:
			if self.__keysize==8:
				self.__key1=pyDes.des(key)
			else:
				if self.__keysize==16:
					self.__key1=pyDes.triple_des(key)
				else:
					raise ValueError("Invalid key size,ANSIX99 need 8 or 16 bytes")


	def mac(self,data):
		if len(data)%8>0:
			data=data+(8-len(data)%8)*'\0'
		data=self.getIV()+data
		f_dae=lambda a,b:self.__key1.encrypt(''.join(map(lambda x,y:chr(ord(x)^ord(y)),a,b)))
		buf=reduce(f_dae,[data[x:x+8] for x in range(0,len(data),8)])
		if self.getMode()==ANSI_X919:
			buf=self.__key1.encrypt(self.__key2.decrypt(buf))
		return buf

if __name__=='__main__':
	from binascii import hexlify,unhexlify
	import sys
	if len(sys.argv)!=3:
		print "Usage:",sys.argv[0],"mackey macdata"
		sys.exit(0)
		
	mackey,macdata=sys.argv[1:]

	m=mac(unhexlify(mackey),ANSI_X99)
	print 'ANSI x9.9',hexlify(m.mac(macdata)).upper()

	m=mac(unhexlify(mackey),ANSI_X919)
	print 'ANSI 9.19',hexlify(m.mac(macdata)).upper()

