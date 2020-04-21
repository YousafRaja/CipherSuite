import os
import struct
from pathlib import Path

from sympy.crypto import rsa_private_key, rsa_public_key, encipher_rsa, decipher_rsa
from sympy.ntheory import isprime

import sympy
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import *
import random
from sympy import primitive_root

TTP_listen_port = 31802
TTP_address = '127.0.4.18'
server_listen_port = 31803
server_address = '127.0.4.18'
client_response_port = 10704
signRequest = "REQUEST_SIGN"
keyRequest = "REQUEST_KEY"

def getSalt(): # 16 bytes = 128 bits
    r = 1
    for _ in range(127):
        r<<=1
        r|= random.randrange(0,2)
    return r

def getqUpper(): # return 1..(x509)..1
    r = 1
    for _ in range(509):
        r<<=1
        r |=1
    r <= 1
    return r | 1

def getqLower(): # return 1..(x509)..1
    r = 1
    r <<=509
    r <= 1
    return r | 1

def bytesToStringArr(bytes):
    if(bytes==None):return ""
    client_msg = bytes.decode("utf-8")
    return client_msg.split(',')

def numbersToByteArr(nums):
    if(len(nums)==0):return ""
    r = str(nums[0])
    for i in range(1,len(nums)):
        r += "," +str(nums[i])
    ba = bytearray()
    ba.extend(map(ord, r))
    return ba

def concateByteArray(nums):
    r = bytearray()
    for n in nums:
        while(n):
            t = n&0xf
            r.append(t)
            n>>=4
    return r

def getCryptoRand_OLD(): # TO-DO: update with real rand
    return random.randrange(0, N)

def H512client(a):
    t = hashes.Hash(hashes.SHA512(), default_backend())
    t.update(concateByteArray(a))
    t = t.finalize()
    return int.from_bytes(t,byteorder='big')

def H512(a): # a = ([name, PK])
    t = hashes.Hash(hashes.SHA512(), default_backend())
    t.update(concateByteArray(a))
    t = t.finalize()
    t_prime = hashes.Hash(hashes.SHA512(), default_backend())
    t_prime.update(t)
    t_prime = t_prime.finalize()
    tt = concateByteArray([int.from_bytes(t, byteorder='big'),int.from_bytes(t_prime, byteorder='big')])
    tt = int.from_bytes(tt, byteorder='big')
    return tt

def H(a):
    t = hashes.Hash(hashes.SHA3_256(), default_backend())
    B = concateByteArray(a)
    t.update(B)
    t = t.finalize()
    return int.from_bytes(t, byteorder='big')
    #value = struct.unpack("<I", bytearray(t[0:4]))[0]
    #return value

def encodeLBytes(n):
    ba = bytearray(str(n).encode('utf-8'))
    l = len(ba)
    l = l.to_bytes(4, byteorder='big')
    r = l+ba
    return r

def getBitLength(n):
    r = 1
    while(n):
        n>>=1
        r +=1
    return r

def getCryptoRand(): # return true random number between 0 and N-1
    #/dev/urandom uses cryptographically suitable pseudo-random number generation (PRNG)
    # is the preferred source of cryptographic randomness on UNIX-like systems
    # prefered over /dev/random which is true randomness but may not have enough entropy
    r = 0
    for _ in range(nL):
        r |= (int.from_bytes(os.urandom(1), byteorder='big', signed=False))%2
        r<<=1
    return r%N



def RSA_encrypt(msg, key): return encipher_rsa(msg, key)

def RSA_decrypt(msg, key): return decipher_rsa(msg, key)

def RSA_sigGen():
    return

def RSA_verify():
    return



q, N, g, k, nL =0, 0, 0, 0, 0

def getSafePrime():
    global q, N, g, k, nL
    N = 0 # reset N value
    debugQ = 1934612908853690825129813706743369339572623046436438804635475902776127289753690923461022278840020158254912758317724313673982950952171118802373834636546381
    debugQ2 = 1934612908853690825129813706743369339572623046436438804635475902776127289753690923461022278840020158254912758317724313673982950952171118802373834636546381
    print("Finding a safe prime, this usually takes under 30 seconds.")
    while not (isprime(N)):
            if __debug__:
                q = sympy.randprime(lower, upper) #DEBUG OFF
            else:
                q = debugQ #DEBUG ON
            N = 2*q + 1
    print("Found :",q)

    g = primitive_root(N)
    k = H([N, g])
    nL = getBitLength(N)
    return N

rsa_N, rsa_p, rsa_q = 0, 0, 0
rsa_d, rsa_e = 0, 0
rsa_puk, rsa_prk = 0, 0

def usend(pa, fn, sock, name, recPort, splitter):

    #sock.settimeout(10.0)
    recv_msg = ""
    server_msg = bytearray()

    # Send data
    print(name +': sending ', pa[0])
    message = 0
    message = numbersToByteArr(pa[0]) if splitter=="," else pa[0]
    sock.sendall(message)
    data = sock.recv(recPort)
    server_msg += data
    print(name +': received {!r}'.format(data))
    server_msg =bytesToStringArr(server_msg) if splitter=="," else server_msg
    pa[0] = server_msg
    return fn(pa)

def RSA_keyGeneration(e):
    global rsa_N, rsa_p, rsa_q, rsa_d, rsa_e, rsa_puk, rsa_prk
    rsa_p = getSafePrime()
    rsa_q = getSafePrime()
    rsa_N = rsa_p*rsa_q
    rsa_e = e
    # create RSA key pair
    rsa_N, rsa_d = rsa_private_key(rsa_p, rsa_q, rsa_e, totient='Euler')
    rsa_N, rsa_e = rsa_public_key(rsa_p, rsa_q, rsa_e, totient='Euler')
    rsa_puk = (rsa_N, rsa_d)
    rsa_prk = (rsa_N, rsa_e)


getN = "g" # get generated registration values
getC = "c" # get certificate

#while(not g):
#    randNum = random.randrange(1000, 9999)
#    q = prime(randNum)
#    N = 2*q+1
#    g = primitive_root(N)
#   k = H([N,g])
I, S, sState, p = 0, 0, 0, 0
lower, upper = getqLower(), getqUpper()
debugQ = 2778119988067355276391298842288103973178184363640580676667590201767815041500827426559516408545308793496250012426762288567287096106215577877121316539807353


#print("Searching for a suitable prime number, shouldn't take more than a minute.")
#while not (isprime(N) and isprime(q)):
    #q = random.randrange(lower, upper)
#    q = debugQ
#    N = 2*q + 1

#g = primitive_root(N)
#k = H([N, g])
#nL = getBitLength(N)

#print(getCryptoRand())


# File Encryption #
def encryptFile(plaintext_filename, sharedKey):
    data = Path(plaintext_filename).read_bytes()  # Python 3.5+
    return hashEncrypt(str(data)[2:-1], sharedKey)


def decryptFile(iv, ctxt, sharedKey):
    k = getKey(sharedKey)
    cipher = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ctxt) + decryptor.finalize()
    lastByte = pt[-1:];
    nextByte = pt[-1:];
    i = -1
    while (lastByte == nextByte):
        i -= 1
        nextByte = (pt[i:i + 1]);

    #unpadder = padding.PKCS7(256).unpadder()
    #pt1 = unpadder.update(pt)
    return str(pt[:-32 + i+1])


def toByteArray(plaintext):
    B = bytearray(plaintext.encode('utf-8'))
    return B

def getKey(pw):
    k = hashes.Hash(hashes.SHA3_256(), default_backend())
    k.update(pw.to_bytes(512, byteorder='big'))
    k = k.finalize()
    #k = k[0:16]# 128 bits = 16 bytes
    return k

def hashEncrypt(plaintext, sharedKey):
    # a) Convert plaintext to a byte array B
    B = toByteArray(plaintext)
    # b) Compute hash tag t by applying SHA1 to B, append t to B
    t = hashes.Hash(hashes.SHA3_256(), default_backend())
    t.update(B)
    t = t.finalize()
    B.extend(t)
    # c) Derive key by applying SHA1 to password, truncate results for AES-128
    k = getKey(sharedKey)
    # d) Generate 16 byte random IV, write to a file F
    iv = os.urandom(16);
    # e) Pad B w/ PKCS7, encrypt with AES-128-CBC, append to F
    pad_ob = padding.PKCS7(256).padder()
    msg_pad = pad_ob.update(bytes(B))
    msg_pad += pad_ob.finalize()
    cipher_ob = Cipher(algorithms.AES(k), modes.CBC(iv), default_backend())
    aes_encryptor = cipher_ob.encryptor();
    ctxt = aes_encryptor.update(msg_pad);
    return iv+ctxt
    #Path(ciphertext_filename).write_bytes(res)