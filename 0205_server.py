# 公開鍵の送受信には成功
# base64のエンコードに成功
# pyramidもsao_1.jpgも送信可能
# RSA完成
import Crypto.PublicKey.RSA as RSA
import Crypto.Util.randpool as RANDOM
import socket
from datetime import datetime
import struct
import os
import base64
import hashlib
from Crypto.Cipher import AES

# address = ('192.168.11.2', 10000)
address = ('127.0.0.1', 10000)
max_size = 1024*5


def dec_rsa(rsa, encrypto):
    rsa_private_key = RSA.construct((rsa.n, rsa.e, rsa.d))
    decrypto = rsa_private_key.decrypt(encrypto)
    return decrypto


def dec_aes(cipher_data_base64, key, iv):
    cipher_data = base64.b64decode(cipher_data_base64)
    # secret_key = hashlib.sha256(key.encode('utf-8')).digest()
    secret_key = hashlib.sha256(key).digest()
    iv = hashlib.md5(iv.encode('utf-8')).digest()
    crypto = AES.new(secret_key, AES.MODE_CBC, iv)
    message64_16byte = crypto.decrypt(cipher_data)
    message64 = message64_16byte.split("_".encode('utf-8'))[0]
    message = base64.b64decode(message64)
    return message


if __name__ == '__main__':
    if os.path.isfile('./text0.jpg'):
        os.remove('./text0.jpg')
    print('Starting the server at', datetime.now())
    print('Waiting for a client to call.')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(address)
    server.listen(5)
    client, addr = server.accept()
    # 公開鍵を送信
    rsa = RSA.generate(1024, RANDOM.RandomPool().get_bytes)
    rsa_pub_key = rsa.publickey()
    rsa_pub_key_send = rsa_pub_key.exportKey()
    print('rsa_pub_key_send')
    print(rsa_pub_key_send)
    client.send(rsa_pub_key_send)
    # セッション鍵を受信
    data = client.recv(max_size)
    client.send('OK'.encode('UTF-8'))
#    dec=dec_rsa(rsa,data)
#    secret_key=base64.b64decode(dec)
    secret_key = dec_rsa(rsa, data)
    print(secret_key)
    # ループ回数を受信
    num = client.recv(max_size)
    client.send(num)
    allsize = struct.unpack('H', num)
    print(allsize)
    # 書き込みモードで開く
    f = open('text0.jpg', 'ab')
    # 暗号文を受信
    for i in range(allsize[0]):
        enc_a = client.recv(max_size)
        j = struct.pack('H', i)
        print(i)
        f.write(enc_a)
        client.send(j)
    f.close()
    iv = 'hoge'
    f = open('text0.jpg', 'rb')
    a = f.read()
    f.close()
    b = dec_aes(a, secret_key, iv)
    print(b)
    f = open("hybridfile.jpg", "wb")
    f.write(b)
    f.close()
    client.sendall(b"Finish")
    client.close()
    server.close()
