import random
import secrets
import socket
import sys
import time
from pathlib import Path

import sympy

import sys
import util

from sympy import primitive_root
from sympy.ntheory import isprime
signedCert = 0
util.S = "The Server"
util.sState = 0
plaintextFile = 'serverFile.txt'
def register_client(m, client_map):
    # m = (      I,         0 - s,    1-v, 2-A, 3-b,4-Ks,5-B)
    client_map[m[0]] = [int(m[1]), int(m[2]), -1, -1, -1, -1]



def ack_client(m,client_map):
    # m = (I, A)
    m[1] = util.decipher_rsa(int(m[1]),(util.N, util.rsa_d))
    s = client_map[m[0]][0]
    v = client_map[m[0]][1]
    client_map[m[0]][2] = m[1]
    b = util.getCryptoRand()
    client_map[m[0]][3] = b  # set b for later
    B = util.k*v + pow(util.g,b,util.N)
    client_map[m[0]][5] = B  # set B for later
    return util.numbersToByteArr([s, B])

def auth_successful(m1, clientMap):
    for key in clientMap:
        m = clientMap[key]
        return util.numbersToByteArr([util.H([m[2], int(m1[0]), m[4]])])
    return None

def check_challenge(m1, clientMap):
    # m1 - client's response, assuming just 1 client and called in right order
    for key in clientMap:
        m = clientMap[key]
        A = m[2]
        v = m[1]
        b = m[3]
        B = m[5]
        u = util.H([A, B]) % util.N
        Kserv = pow(A*(pow(v, u, util.N)), b, util.N)
        m[4] = Kserv
        m0 = util.H([A, B, Kserv])
        return int(m1[0])==m0
    return None

def getPlainText(client_msg, clientMap):
    data = client_msg[0]
    iv = data[:16]
    ctxt = data[16:]
    Kserv = -1
    for key in clientMap:
        m = clientMap[key]
        Kserv = m[4]
    return util.decryptFile(iv, ctxt, Kserv)

def start(client_map):
    # Create a TCP/IP socket
    global signedCert
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (util.server_address, util.server_listen_port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    while True:
        sock.listen(1)
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            client_msg = bytearray()

            print('connection from', client_address)

            # Receive the data in small chunks and retransmit it
            while True:
                data = connection.recv(1024)
                print('server: received {!r}'.format(data))
                client_msg = util.bytesToStringArr(data) if util.sState!=4 else [data]
                if(len(client_msg)==3 and util.sState == 1):
                    print('server: registering client')
                    register_client(client_msg, client_map)
                    connection.sendall(util.numbersToByteArr(["registered"]))
                    util.sState = 2
                elif(len(client_msg)==2 and util.sState == 3):
                    print('server: acknowledging client')
                    connection.sendall(ack_client(client_msg, client_map))
                elif (len(client_msg) == 1 and client_msg[0]==util.getN and util.sState == 0):
                    print('server: sending initial parameters')
                    connection.sendall(util.numbersToByteArr([util.q, util.N, util.g, util.k, util.nL]))
                    util.sState = 1
                elif (len(client_msg) == 1 and util.sState == 2):
                    print('server: sending signed certificate')
                    #server receives len(I)||Ibytes
                    connection.sendall(signedCert)
                    util.sState = 3
                elif (len(client_msg) == 1 and client_msg[0]!='' and util.sState==3):
                    print('server: checking challenge')
                    if(check_challenge(client_msg,client_map)):
                        print('server: passed challenge, sending confirmation')
                        connection.sendall(auth_successful(client_msg, client_map))
                        util.sState = 4
                    else:
                        print('server: failed challenge')
                elif (len(client_msg) == 1 and util.sState == 4):
                    print('server: decrypting message')
                    pt = getPlainText(client_msg, client_map)[2:-1]
                    pt = pt.replace("\\\\", "\\").replace("\\n", "").replace("\\r", "\r").replace("\\\\'","\'").replace("\\\\","\\")
                    f = open(plaintextFile, 'w')
                    print('server: writing to file')
                    f.write(pt)
                    f.close()
                    util.sState = 0
                    connection.sendall(util.numbersToByteArr(["OK"]))
                else:
                    break
                print('server: done')
                #print('no data from', client_address)

def init():
    #print("Setting up parameters, this usually takes under 30 seconds.")
    #while not (util.isprime(util.N)):
    #        util.q = sympy.randprime(util.lower, util.upper)
    #        util.q = debugQ # TO-DO remove this line
    #        util.N = 2*util.q + 1

    #print(util.q)
    #util.g = primitive_root(util.N)
    #util.k = util.H([util.N, util.g])
    #util.nL = util.getBitLength(util.N)
    #util.getSafePrime()
    while True:
        try:
            getCert()
            break
        except ConnectionRefusedError:
            print("Server: Waiting for TTP Cert, will try again.")
            time.sleep(1)

    print("done")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
def getCert():
    global signedCert
    server_address = (util.TTP_address, util.TTP_listen_port )
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    TTP_N_TTP_SIG=send(send([bytes(util.signRequest.encode('utf-8'))], f0), f1)
    TTP_SIG = TTP_N_TTP_SIG[128:]
    ba = bytearray(str(util.S).encode('utf-8'))
    l = len(ba)
    l = l.to_bytes(4, byteorder='big')
    signedCert = l+bytes(util.S.encode('utf-8'))+util.rsa_e.to_bytes(128, byteorder='big')+TTP_SIG

def send(pa, fa):
    return util.usend(pa, fa, sock, "server", util.server_listen_port, "")

def f0(pa): # send cert to be signed
    ba = bytearray(str(util.S).encode('utf-8'))
    l = len(ba)
    l = l.to_bytes(4, byteorder='big')
    if("".join(pa[0].decode("utf-8"))=="OK"):return [l+bytes(util.S.encode('utf-8'))+util.rsa_e.to_bytes(128, byteorder='big')]
    else:
        print("Something went wrong with TTP")
        exit(1)

def f1(pa):return pa[0]

def getServerInfo():
    global plaintextFile
    if __debug__:
        print('Debug OFF')
        util.S = str(input("Please enter server name: "))
        plaintextFile = str(input("Please enter file name: "))
    else:
        print('Debug ON')
        plaintextFile = 'serverFile.txt'
        util.S = "The Server"

def driver():
    getServerInfo()
    util.RSA_keyGeneration(5)
    init()
    client_map = {}
    start(client_map)

driver()

