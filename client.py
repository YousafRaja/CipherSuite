import itertools
import random
import socket
import sys
import time

import util

fmt = "," # "" for A3 code, "," for A2 code
N = -1
plaintext_filename = "clientFile.txt"

def finit():
    return [util.getN]

def f0(pa): # NOTE: The first element in the returned array will be used for sending and receiving server messages.
    util.q, util.N, util.g, util.k, util.nL = int(pa[0][0]), int(pa[0][1]), int(pa[0][2]), int(pa[0][3]), int(pa[0][4])
    s = util.getSalt()
    x = util.H(list(itertools.chain([ord(c) for c in util.p], [s])))
    v = pow(util.g,x,util.N)
    del x
    return [(util.I,s,v),util.I,s,v,util.g]

def f0a(pa): # set pa[0] to len(I)||Ibytes and return pa
    global fmt
    fmt = ""
    ba = bytearray(util.I.encode('utf-8'))
    l = len(ba)
    l = l.to_bytes(4, byteorder='big')
    pa[0] = (l+bytes(util.I.encode('utf-8')))
    return pa



def f0b(pa): # check certificate with TTP, return pa
    global sock
    global fmt
    data = pa[0]
    ln = int.from_bytes(data[:4], byteorder='big')
    S_Name = int.from_bytes(data[4:4 + ln], byteorder='big')
    S_PuK = int.from_bytes(data[4 + ln:4 + ln + 128], byteorder='big')
    TTP_SIG = int.from_bytes(data[4 + ln + 128:], byteorder='big')

    sock.close()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (util.TTP_address, util.TTP_listen_port )
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
    sock.sendall(bytes(util.keyRequest.encode('utf-8')))
    data = sock.recv(util.client_response_port)
    sock.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (util.server_address, util.server_listen_port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    TTP_N = int.from_bytes(data[:128], byteorder='big')
    TTP_PuK = int.from_bytes(data[128:], byteorder='big')

    sigFromHash = util.RSA_decrypt(util.H512([S_Name,S_PuK])% TTP_N, (TTP_N,TTP_PuK))

    if(TTP_SIG==sigFromHash):
        fmt = ","
        print("Verification: Success")
        util.I = pa[1]
        a = util.getCryptoRand()
        pa.append(a)
        g = pa[4]
        A = pow(g, a, util.N)
        pa.append(A)
        A = util.encipher_rsa(A, (util.N, S_PuK))
        pa[0] = [util.I, A]
        return (pa)
    else:
        print("Verification: Failed")
        exit(1)


#def f1(pa): # send rsa encrypt of A
 #   util.I = pa[1]
 #   a = util.getCryptoRand()
 #   pa.append(a)
#    g = pa[4]
#    A = pow(g, a,util.N)
#    pa.append(A)
#    pa[0] = [util.I, A]
#    return (pa)

def f2(pa): # called after getting (s, B)
    B, I, s, v, g, a, A =int(pa[0][1]), pa[1], int(pa[0][0]), pa[3], pa[4], pa[5], pa[6]
    u = util.H([A,B])%util.N
    x = util.H(list(itertools.chain([ord(c) for c in util.p], [s])))
    Kclient = pow((B-util.k*v),a+u*x, util.N)
    pa.append(Kclient)
    m1 = util.H([A,B,Kclient])
    pa.append(m1)
    pa[0] = [m1]
    return pa

def f3(pa):
    global fmt
    fmt = ""
    m2, A, Kclient, m1 = pa[0], pa[6], pa[-2], pa[-1]
    if util.H([A, m1, Kclient])==int(m2[0]):
        print("Client: Success")
        pa[0] = [util.encryptFile(plaintext_filename, Kclient)]
        return pa[0]
    else:
        print("Client: Not Success")
        exit(1)

def f4(pa):
    print("Client: Done")


def osend(pa, fn):

    #sock.settimeout(10.0)
    recv_msg = ""
    server_msg = bytearray()

    # Send data
    print('client: sending ', pa[0])
    message = util.numbersToByteArr(pa[0])
    sock.sendall(message)
    data = sock.recv(1024)
    server_msg += data
    print('client: received {!r}'.format(data))
    server_msg = util.bytesToStringArr(server_msg)
    pa[0] = server_msg
    return fn(pa)




def register():
    s= random.randrange(1000, 9999) # needs to be cryptographically suitable random
    x = util.H(list(itertools.chain([ord(c) for c in util.p], [s])))
    v = pow(util.g,x,util.N)
    #send((I, s, v))

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def send(pa, fa):
    return util.usend(pa, fa, sock, "client", util.client_response_port, fmt)

def driver():
    getUserInfo()
    # Connect the socket to the port where the server is listening
    server_address = (util.server_address, util.server_listen_port)
    print('connecting to {} port {}'.format(*server_address))
    while True:
        try:
            sock.connect(server_address)
            break
        except ConnectionRefusedError:
            print("Client: Waiting for server, will try again.")
            time.sleep(1)
    send(send(send(send(send(send(finit(),f0), f0a), f0b), f2), f3), f4)
    sock.close()

def getUserInfo(): # - TO-DO: get user input
    if __debug__:
        print('Debug OFF')
        util.I = str(input("Please enter username: "))
        util.p = str(input("Please enter password: "))
    else:
        print('Debug ON')
        util.I = 'abc'
        util.p = '123'


driver()