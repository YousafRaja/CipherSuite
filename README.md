HOW TO RUN:

Open a new terminal and run python -u TTP.py

Open a new terminal and run python -u Server.py

Open a new terminal and run python -u client.py

The contents in clientFile.txt should now appear in serverFile.txt

NOTE:
- To enable debug mode, run with -O flag (i.e python -O -u client.py), in this mode it will start up faster by using pre-defined values.

client.py - The client connects to the Serverand verifies the identity of the server by checking with the TTP (trusted third party). The client then reads from clientFile.txt and sends the server the encrypted contents.
clientFile.txt - The information to send to the server
Server.py - The server gets a signed signature from TTP which it sends to the client for authentication. It then decrypts the message sent from the client and writes it to serverFile.txt.
serverFile.txt - The decryption information received from the client
TTP.py - Provides the server's authentication to the client. 
util.py
- provides shared functionality between the 3 scripts
- sets port numbers
 
