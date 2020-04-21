import socket
import sys
import util

from sympy.crypto.crypto import rsa_private_key, rsa_public_key



def start():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_address = (util.TTP_address, util.TTP_listen_port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # Listen for incoming connections
    while True:
        sock.listen(1)
        while True:
            # Wait for a connection
            print('TTP: waiting for a connection')
            connection, client_address = sock.accept()
            client_msg = bytearray()

            print('TTP: connection from', client_address)

            # Receive the data in small chunks and retransmit it
            while True:
                data = connection.recv(1024)
                print('TTP: received {!r}'.format(data))
                client_msg = "".join(util.bytesToStringArr(data))
                if(client_msg==util.signRequest):
                    connection.sendall(util.numbersToByteArr(["OK"]))
                    data = connection.recv(1024) # get len(name)(4 byte)|name|PK(128 byte)
                    ln = int.from_bytes(data[:4], byteorder='big')
                    name = int.from_bytes(data[4:4+ln], byteorder='big')
                    pk = int.from_bytes(data[4+ln:4+ln+128], byteorder='big')
                    sig = util.RSA_decrypt(util.H512([name,pk])% util.rsa_N, util.rsa_prk)
                    signedCert = util.rsa_N.to_bytes(128,byteorder='big')+sig.to_bytes(128,byteorder='big')
                    connection.sendall(signedCert)
                elif(client_msg==util.keyRequest):
                    response = util.rsa_N.to_bytes(128,byteorder='big')+util.rsa_e.to_bytes(128,byteorder='big')
                    connection.sendall(response)
                connection.close()
                break


def main():
    util.RSA_keyGeneration(17)
    start()

main()
