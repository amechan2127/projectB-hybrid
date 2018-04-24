#公開鍵の送受信には成功
#base64のエンコードに成功
#pyramidもsao_1.jpgも送信可能
#RSA完成
import Crypto.PublicKey.RSA as RSA
import Crypto.Util.randpool  as RANDOM
import datetime,time
import time
import socket
from datetime import datetime
from struct import *
import time
import os
import base64
import hashlib
from Crypto.Cipher import AES
from signal import signal, SIGPIPE, SIG_DFL
signal(SIGPIPE,SIG_DFL)

def enc_rsa(pub_key,message):
	encrypto = pub_key.encrypt( message, "" )
	return encrypto

def enc_aes(message,key,iv):
	message64=base64.b64encode(message)#16byte
	if len(message64) % 16 != 0:
		message64_16byte = message64
		for i in range(16-(len(message64) % 16)):
			message64_16byte += "_".encode('utf-8')
	else:
		message64_16byte = message64
	secret_key = hashlib.sha256(key.encode('utf-8')).digest()
	iv = hashlib.md5(iv.encode('utf-8')).digest()
	crypto = AES.new(secret_key,AES.MODE_CBC,iv)
	cipher_data = crypto.encrypt(message64_16byte)
	cipher_data_base64 = base64.b64encode(cipher_data)
	return cipher_data_base64


if __name__ == '__main__':
	if os.path.isfile('text1.jpg'):
	    os.remove('text1.jpg')
		
	#address = ('192.168.11.2', 10000)
	address = ('127.0.0.1', 10000)
	#address = ('169.254.17.32', 10000)
	max_size = 4096
	size=500

	#AESで暗号化
	iv="hoge"
	secret_key = "Awesome Python!!"
	f=open('./pyramid.jpg', 'rb')
	data = f.read()
	f.close()

	enc_a=enc_aes(data,secret_key,iv)
	f.write(enc_a)
	f.close()

#	秘密鍵にbase64を適用
#	message=base64.b64encode(secret_key)

	#通信開始
	print('Starting the client at', datetime.now())
	client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client.connect(address)

	#公開鍵の受信
	rsa_pub_key_recv = RSA.importKey(client.recv(max_size))
	print('rsa_pub_key_recv')
	print(rsa_pub_key_recv)

	#秘密鍵を公開鍵で暗号化、セッション鍵を送信　　　　　　ここでエラー発生！
	enc_r=enc_rsa(rsa_pub_key_recv,secret_key)
	client.send(enc_r[0])

	#ループ回数を送信
	start = time.time()
	end=int(len(enc_a)/size)+1
	all_data=len(enc_a)
	l=pack('H',end)
	client.send(l)
	a1=client.recv(max_size)
	print(all_data)
	print(size) 
	#暗号文を送信     
	for d in range(end):
		enc=enc_a[d*size:(d+1)*size]
		client.send(enc)
		r=client.recv(max_size)
		print(unpack('H',r))
	elapsed_time= time.time() -start
	print("elapsed_time:{0}".format(elapsed_time)+"{sec}")
	print('finish')
	data = client.recv(max_size)
	print('At', datetime.now(), 'someone replied', data)
	client.close()

