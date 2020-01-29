# -*- coding: utf-8 -*-
"""
@author: simon
"""

from ctypes import c_uint32
import math
import itertools


def xor_Pair(a,b):
    w = c_uint32(a[0])
    x = c_uint32(a[1])
    y = c_uint32(b[0])
    z = c_uint32(b[1])
    return [w.value^y.value,x.value^z.value]

def encrypt_ECD(plaintext,key):
    if not plaintext:
            return ''
    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])
    cipher = []
    for chunk in _chunks(v,2):
        cipher += encipher(chunk,k)
    return cipher

def decrypt_ECD(ciphertext,key):
    if not ciphertext:
        return ''
    k = _str2vec(key.encode()[:16])
    message = []
    for chunk in _chunks(ciphertext,2):
        message += decipher(chunk,k)
    return _vec2str(message).decode()
                               
def encrypt_CBC(plaintext,key,IV):
    if not plaintext:
            return ''
    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])
    cipher = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(v,2):
        previous = encipher(xor_Pair(chunk,previous),k)
        cipher += previous
    return cipher

def decrypt_CBC(ciphertext,key,IV):
    if not ciphertext:
        return ''
    k = _str2vec(key.encode()[:16])
    message = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(ciphertext,2):
        message += xor_Pair(decipher(chunk,k),previous)
        previous = chunk
    return _vec2str(message).decode()

def encrypt_OFB(plaintext,key,IV):
    if not plaintext:
            return ''
    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])
    cipher = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(v,2):
        previous = encipher(previous,k)
        cipher += xor_Pair(previous,chunk)
    return cipher

def decrypt_OFB(ciphertext,key,IV):
    if not ciphertext:
        return ''
    k = _str2vec(key.encode()[:16])
    message = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(ciphertext,2):
        previous = encipher(previous,k)
        message += xor_Pair(previous,chunk)
    return _vec2str(message).decode()

def encrypt_CFB(plaintext,key,IV):
    if not plaintext:
            return ''
    v = _str2vec(plaintext.encode())
    k = _str2vec(key.encode()[:16])
    cipher = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(v,2):
        previous=xor_Pair(chunk,encipher(previous,k))
        cipher += previous
    return cipher
    
def decrypt_CFB(ciphertext,key,IV):
    if not ciphertext:
        return ''
    k = _str2vec(key.encode()[:16])
    message = []
    previous=[IV[0],IV[1]]
    for chunk in _chunks(ciphertext,2):
        message += xor_Pair(encipher(previous,k),chunk)
        previous = chunk
    return _vec2str(message).decode()

def encipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0)
    delta = 0x9e3779b9
    n = 32  #64 rounds
    w = [0,0]
    while(n>0):
        sum.value += delta
        y.value += ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        z.value += ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        n -= 1
    w[0] = y.value
    w[1] = z.value
    return w

def decipher(v, k):
    y = c_uint32(v[0])
    z = c_uint32(v[1])
    sum = c_uint32(0xc6ef3720)
    delta = 0x9e3779b9
    n = 32
    w = [0,0]
    while(n>0):
        z.value -= ( y.value << 4 ) + k[2] ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3]
        y.value -= ( z.value << 4 ) + k[0] ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1]
        sum.value -= delta
        n -= 1
    w[0] = y.value
    w[1] = z.value
    return w

def _str2vec(value, l=4):   #a binary string to a vector
    #separates in chunks of 4 chars
    #each chunks contain the binary values of each character, in reversed order (it's itf-8, so check hexa value and calculate binary)
    #put together, they give a number in decimal
    n = len(value)
    # Split the string into chunks
    num_chunks = math.ceil(n / l)
    chunks = [value[l * i:l * (i + 1)]
              for i in range(num_chunks)]
    return [sum([character << 8 * j
                 for j, character in enumerate(chunk)])
            for chunk in chunks]
    
def _vec2str(vector, l=4):  #a vector to a binary string
    return bytes((element >> 8 * i) & 0xff
                 for element in vector
                 for i in range(l)).replace(b'\x00', b'')

def _chunks(iterable, n):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, n))
        if not chunk:
            return
        yield chunk

def padding(m): 
    size = len(m)
    if(size%8 >0 and size > 0):
        while(size%8 > 0):
            m=m+' '
            size+=1
    return m

def undoPadding(m):
    while(m[len(m)-1]==' '):
        m=m[:-1]
    return m

if __name__ == "__main__":
    """modes : ECD, CBC, OFB, CFB"""
    encryptionMode = 'OFB'
    
    """The key must be 16 characters"""
    key = '123456789abcdef'
    
    """The message must be a non-empty utf-8 string"""
    plainTextMessage = "Test message"
    
    """Initial value must be 2 times 8 characters"""
    IV = [12345678,87654321]
    
    plainTextMessage=padding(plainTextMessage)
    
    if(encryptionMode=='ECD'):
        enc = encrypt_ECD(plainTextMessage, key)
        dec = decrypt_ECD(enc,key)
    elif(encryptionMode == 'CBC'):
        enc = encrypt_CBC(plainTextMessage, key,IV)
        dec = decrypt_CBC(enc,key,IV)
    elif(encryptionMode == 'OFB'):
        enc = encrypt_OFB(plainTextMessage, key,IV)
        dec = decrypt_OFB(enc,key,IV)
    elif(encryptionMode == 'CFB'):
        enc = encrypt_CFB(plainTextMessage, key,IV)
        dec = decrypt_CFB(enc,key,IV)
    
    plainTextMessage = undoPadding(plainTextMessage)
    dec=undoPadding(dec)
    
    print("original : ",plainTextMessage)
    print("cryptogram : ",enc)
    print("decrypted : ",dec)
    if (plainTextMessage==dec) :
        print("It worked !")
    else :
        print("It didn't work...")

