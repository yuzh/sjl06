#encoding=utf8
import sys
import unittest
import emu_hsm
"""
2013-5-23 初次创建
2013-5-29 humx 新增62测试
"""
HSM=emu_hsm.Hsm('10.112.9.249.hsm')
class HsmFunctionTest(unittest.TestCase):
	def setUp(self):
		self.hsm=HSM

	def test_HR(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

	def test_1E(self):
		# clear=0123456789ABCDEF
		# cipher/MK=1C0BE608104E8118
		# data clear=0000000000000000
		# data cipher=D5D44FF720683D0D

		# normal
		req='1E'+'1'+'1'+'1C0BE608104E8118'+'1'+'D5D44FF720683D0D'
		expect='1F00B6D1898291A4EF73FCB2E54831F3EC60'
		ret=self.hsm.handle(req)
		self.assertEqual(ret,expect)
		# invalid convert mode (1|2)
		for mode in '0123':
			req='1E'+mode+'1'+'1C0BE608104E8118'+'1'+'D5D44FF720683D0D'
			expect='1F00B6D1898291A4EF73FCB2E54831F3EC60'
			if mode not in '12':
				expect='1F77'
			ret=self.hsm.handle(req)
			self.assertEqual(ret,expect)

	def test_2A(self):
		# clear=0123456789ABCDEF
		# cipher/lmk=D5D44FF720683D0D
		# normal
		req='2A'+'K'+'20D'+'1'+'1C0BE608104E8118' # agent 0106's zak2 on 18.22
		expect='2B00D5D44FF720683D0D'
		ret=self.hsm.handle(req)
		self.assertEqual(ret,expect)

	def test_2C(self):
		# normal
		req='2C'+'K'+'209' # agent 0106's zmk on 18.22
		expect='2DE0E1053BBECCF300FA4D02420CD3F8467C33B62318131DA'
		ret=self.hsm.handle(req)
		self.assertEqual(ret,expect)
		# invalid index
		d={'a':'2D61','aaa':'2D33','2099':'2D62'}
		for k in d.keys():
			req='2C'+'K'+k # agent 0106's zmk on 18.22
			expect=d[k]
			ret=self.hsm.handle(req)
			self.assertEqual(ret,expect)

	def test_3A(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

	def test_60(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

	def test_62(self):
		#clear1:0123456789ABCDEF
		#clear2:FEDCBA9876543210
		#PIN1格式:01
		#pin1block1:0592389FFFFFFFFF
		#pin1block2:0000400000123456
		#pin1:0592789fffedcba9
		#pin1cipher:5D1B629D084CF4AE
		#pin1 12:400000123456
		#pin2格式：02
		#pin2:5923890987654321
		#pin2chiper:CC37FA2D700E204E

		req = '62'+'1'+'0123456789ABCDEF'+'1'+'FEDCBA9876543210'+'01'+'02'+'5D1B629D084CF4AE'+'400000123456'
		expect = '63'+'00'+'CC37FA2D700E204E'
		ret=self.hsm.handle(req)
		self.assertEqual(ret,expect)

	def test_68(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

	def test_80(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

	def test_82(self):
		ret=self.hsm.handle('HR')
		self.assertEqual(ret[:4],'HS00')

if __name__=='__main__':
	unittest.main()
