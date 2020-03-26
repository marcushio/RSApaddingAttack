from Crypto.Util.number import long_to_bytes
import argparse
import time
import socket
import sys
from aes import AESCipher
from Crypto.PublicKey import RSA
#make some masks
ones = int( '1' * 255 )
andmask = ((1 << 255) & ones) - 1
ormask = (1<<255)
ones = int('1' * 2048)
bigandmask = ((1 << 2049)) -1

def sendMessage(shiftedCipher, encryptedTestMessage):
        # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect the socket to the port where the server is listening
    server_address = (args.ipaddress, int(args.port))
    sock.connect(server_address)
    sock.settimeout(2)
    try:
        # Send data
        msg = shiftedCipher + encryptedTestMessage
        # msg: my shifted cipher + my encrypted test message    
        if args.verbose is True:
            #print('Sending: {}'.format(message.hex()))
            ('Sending: {}'.format(encryptedTestMessage.hex()))
        sock.sendall(msg)
    
        # Look for the response
        amount_received = 0
        amount_expected = len(encryptedTestMessage)
    
        if amount_expected % 16 != 0:
            amount_expected += (16 - (len(encryptedTestMessage) % 16))
    
        answer = b''
        if amount_expected > amount_received:
            while amount_received < amount_expected:
                try:
                    data = sock.recv(MESSAGE_LENGTH)
                except socket.timeout as e:
                    err = e.args[0]
    
                    if err == 'timed out':
                        print('Connection timed out, waiting for retry',
                              file=sys.stderr)
                        time.sleep(1)
                        continue
                    else:
                        print('Another issue: {}'.format(e),
                              file=sys.stderr)
                        break
                except socket.error as e:
                    print('Socket error: {}'.format(e),
                          file=sys.stderr)
                    break
                amount_received += len(data)
                answer += data
        print('Received: {}'.format(aes.decrypt(answer)))
        print( str(aes.decrypt(answer)) )
    
    finally:
        sock.close()
    return str(aes.decrypt(answer))
 

# Handle command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("-ip", "--ipaddress",
                    help='ip address where the server is running',
                    default='127.0.0.1',  # Defaults to loopback
                    required=True)
parser.add_argument("-p", "--port",
                    help='port where the server is listening on',
                    required=True)
parser.add_argument("-f", "--publickey",
                    help='name of public key',
                    default='serverPublicKey',
                    required=False)
parser.add_argument("-v", "--verbose",
                    help="print out extra info to stdout",
                    default='True',
                    required=False)

args = parser.parse_args()

# load server's public key
serverPublicKeyFileName = args.publickey
key = ""
with open(serverPublicKeyFileName, 'r') as f:
    key = RSA.importKey(f.read())

MESSAGE_LENGTH = 2048
#myrawcipher as hex... i sent "boring text"
rawcipher = "5acdc548b13b9799ca193c66532dc75c0eb3125a4dd8c29655c8b9bc3de6e18c6969efb45f039747d043ccbd62eadf1209a82c7adb869423efe4a045015f7b336596e47cb7e59899e4b710349b25a51ea4ea03f952666eaf59d5bd9e44778be31a6315b0d21eda2623e70f35cbee2aff8513c72abe809e268c59c7e1271942f9519ec31a5a5c021ebc14f541c251f657cc97e1c708660bb650db8fe5ae1d994f205af9ded651ac67af11c793dc3d631ae0e324e924dbc3ef58cc233087e561c275f3c284bd281e36eb909a89a2d6618cf92ee09538192db4ebe86b58d71a40c3f2dc31c7e5c501bc52b8fa64fb6626cca82dca49be147ea9b2a55d2eb966910f356de0d32c48ecfdc8e2a89b96e3ddbe"
#turn rawcipher to bytearray
cipher = bytearray.fromhex(rawcipher)
#get the RSA encrypted key part, it's the first 256 bytes
myEncryptedKey = cipher[:256]
#get the encrypted message... tho i don't think i'm going to end up using it til the end
messageEncrypted = cipher[256:]
#shift the cipher 255 for the first round and test with leading key bit being 0
shiftedCipher = long_to_bytes( ((int.from_bytes(myEncryptedKey, 'big') << 255) & bigandmask) ) 
#use the AES key part to encrypt our test message which should be last 32 bytes (256 bit)
num = (1<<255)
trialKey = num.to_bytes(32, 'big')
aes = AESCipher(trialKey)
myEncryptedMessage = aes.encrypt('test')

#this is the basic attack loop here keep looping until we've done all 256 bits
i = 256
while (i > 0):     
    print("Working trial..." + str(i))   
    #see if shiftedCipher works by sending off shiftedCipher + message encrypted with last bit
    #my pattern is to test leading 1 first then change to leading 0
    if sendMessage(shiftedCipher, myEncryptedMessage) == "b'test            '":
        print("no need to shift")
    else: 
        #print("flipping bit from " + str( bin(int.from_bytes(trialKey, 'big'))) )        
        trialKey = (andmask & int.from_bytes(trialKey, 'big')).to_bytes(32, 'big')#flip de leading bit mon
        #print("to                " + str( bin(int.from_bytes(trialKey, 'big'))) )
    #prep for next round 
        #make new key
    trialKey =  (( int.from_bytes(trialKey, 'big') >> 1) + (1 << 255)).to_bytes(32, 'big')
    print("next Key          " + str( bin(int.from_bytes(trialKey, 'big'))) )
        #bit shift the cypher text 
    shiftedCypher = long_to_bytes( (int.from_bytes(myEncryptedKey, 'big') >> 1))
        #encrypt a new message with new key
    aes = AESCipher(trialKey)
    myEncryptedMessage = aes.encrypt('test')       
    i = i-1 

aes = AESCipher(trialKey)
print("final key: " + str( bin(int.from_bytes(trialKey, 'big'))))
theAnswer = aes.decrypt( bytes(messageEncrypted) )
print("the moment of truth... it should say 'boring text' ")
print(theAnswer)
print("if not... key accumulation? fundamental wrong steps in loop? what went wrong?")