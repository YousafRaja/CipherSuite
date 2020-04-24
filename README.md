## What does this show?
One thing this shows is how digitial certificates work. When the client tries to connect to the server, the server will present its certificate which was signed by the TTP (Trusted Third Party, an entity that both the client and server trust).

## What is a Cipher Suite?
A cipher suite is a set of algorithms that add cryptographic security to a network connection. There are typically four components to a cipher suite:

* Key Exchange Algorithm 
* Authentication algorithm (signature)
* Bulk Encryption Algorithm (block cipher and mode of operation)
* Message Authentication Algorithm

Cipher suites are specified in shorthand by a string such as SRP-SHA3-256-RSA-AES-256-CBC-SHA3-256.

This implies SRP-SHA3-256 as the key exchange algorithm, RSA signatures for authentication, AES-256-CBC for encryption and SHA3-256 as the MAC (used as HMAC).


HOW TO RUN:

Open a new terminal and run python -u TTP.py

Open a new terminal and run python -u Server.py

Open a new terminal and run python -u client.py

The contents in clientFile.txt should now appear in serverFile.txt

NOTE:
- To enable debug mode, run with -O flag (i.e python -O -u client.py), in this mode it will start up faster by using pre-defined values.

client.py - The client connects to the Server and verifies the identity of the server by checking with the TTP (trusted third party). The client then reads from clientFile.txt and sends the server the encrypted contents.

clientFile.txt - The information to send to the server

Server.py - The server gets a signed signature from TTP which it sends to the client for authentication. It then decrypts the message sent from the client and writes it to serverFile.txt.

serverFile.txt - The decryption information received from the client

TTP.py - Provides the server's authentication to the client. 

util.py
- provides shared functionality between the 3 scripts
- sets port numbers
 
