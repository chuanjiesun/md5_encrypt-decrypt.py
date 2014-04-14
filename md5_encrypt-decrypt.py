import hashlib, sys, argparse 
from urllib import request
from http import cookiejar
from bs4 import BeautifulSoup as beautifulsoup

def md5_encrypt(clear_text_shuru) : 
	string = clear_text_shuru.encode()

	md5 = hashlib.md5(string).hexdigest()
	print('md5({0}) : {1}'.format(clear_text_shuru,md5))

	sha1 = hashlib.sha1(string).hexdigest()
	print('sha1({0}) : {1}'.format(clear_text_shuru,sha1))

	sha224 = hashlib.sha224(string).hexdigest()
	print('sha224({0}) : {1}'.format(clear_text_shuru,sha224))


	sha256 = hashlib.sha256(string).hexdigest()
	print('sha256({0}) : {1}'.format(clear_text_shuru,sha256))

	sha384 = hashlib.sha384(string).hexdigest()
	print('sha384({0}) : {1}'.format(clear_text_shuru,sha384))

	sha512 = hashlib.sha512(string).hexdigest()
	print('sha512({0}) : {1}'.format(clear_text_shuru,sha512))

def md5_decrypt(encrypt_string):
	headers_somd5 = {
	#POST /somd5-index-md5.html HTTP/1.1
	'x-requested-with': 'XMLHttpRequest',
	'Accept-Language': 'zh-cn',
	'Referer': 'http://www.somd5.com/',
	'Accept': '*/*',
	'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
	'Accept-Encoding': 'gzip, deflate',
	'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
	'Host': 'www.somd5.com',
	#Content-Length: 75 #35+encrypt_string
	'Proxy-Connection': 'Keep-Alive',
	'Pragma': 'no-cache'
	#Cookie: PHPSESSID=ics76oma7inepprp41lsklud36; AJSTAT_ok_times=1; AJSTAT_ok_pages=4; Hm_lpvt_ea66a7f6affa99ee3105d60145d6810d=1397391974; PHPSESSID=6ti1lf38dnlqi8ntsj1uk533i2; Hm_lvt_ea66a7f6affa99ee3105d60145d6810d=1397386712; AJSTAT_ok_pages=3; AJSTAT_ok_times=1
	#isajax=QoG29V7X6mEGHt6Ep8pTI43&md5=40bd001563085fc35165329ea1ff5c5ecbdbbeef
	}
	url_somd5 = 'http://www.somd5.com/somd5-index-md5.html'
	data = 'isajax=QoG29V7X6mEGHt6Ep8pTI43&md5='+encrypt_string
	cj = cookiejar.CookieJar()
	opener = request.build_opener(request.HTTPCookieProcessor(cj))
	req1 = opener.open(url_somd5)
	resp1 = req1.read()
	for a in cj:
		#print(a.name)
		cookie_name = a.name
		#print(a.value)
		cookie_value = a.value
	length = 35+len(encrypt_string)
	data_encode = data.encode()
	req2 = request.Request(url=url_somd5, data = data_encode, headers = headers_somd5,\
				method = 'POST')
	req2.add_header('Content-Length',length)	
	req2.add_header('Cookie',cookie_name+':'+cookie_value)
	resp2 = request.urlopen(req2)
	#print(resp2.info())
	resp2 = resp2.read(1000)
	#print(type(resp2))
	#print(resp2)
	try:
		resp2_decode = resp2.decode(encoding = 'gb18030')
	except:
		resp2_decode = resp2.decode(encoding = 'utf-8')
	
	#print('\n\n\naaaaaaaaaaaaaaa', resp2_decode)
	bs = beautifulsoup(resp2_decode)
	#print(resp2_decode)
	print('开始解密...')
	for b in bs.find_all('h1'):
		#print(b)
		text = b.get_text()
		print('解密后：{}'.format(text))
		sys.exit()
	print('解密失败了...')	
	

def canshu():
	parser = argparse.ArgumentParser(description = 'this is a md5 (en/de)crypt script',\
		usage=''' %(prog)s [options]\
			\nexample:%(prog)s -e clear_text\
			\n	%(prog)s -d encrypt_crypt
			''')
	#parser.add_argument('-e', dest = 'clear text', help = 'specify a string to encrypt')
	#parser.add_argument('-d', dest = 'encrypt string', help = 'specify a string to decrypt'
	group = parser.add_mutually_exclusive_group()
	group.add_argument('-e', dest = 'clear_text', help = 'specify a string to encrypt')
	group.add_argument('-d', dest = 'encrypt_string', help = 'specify a string to decrypt')
	args = parser.parse_args()
	#print(args)#Namespace(clear_text=None, encrypt_string='202cb962ac59075b964b07152d234b70')
	if  args.clear_text or args.encrypt_string:
		if args.clear_text:
			flag = True#加密
			return args.clear_text, flag
		else:
			flag = False#加密
			return args.encrypt_string, flag
		#print(args.clear_text)
	else:
		parser.print_help()
		sys.exit()
	

def main(string_shuru, flag_panduan): 
	if flag_panduan:
		clear_text_shuru = string_shuru 
	#string_encrypt = string_encrypt.encode()
		md5_encrypt(clear_text_shuru)
	else:
		md5_decrypt(string_shuru)

if __name__ == '__main__' :
	canshu_return, flag_return =  canshu()
	#print(canshu_return, flag_return)#202cb962ac59075b964b07152d234b70 False
	main(canshu_return, flag_return)
