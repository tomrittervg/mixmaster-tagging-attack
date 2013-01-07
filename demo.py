#!/usr/bin/python

import hashlib, base64, binascii
import mixKeystore, mixMessage

DoTaggingAttack = True

# ========================================================================
# Specify the keystore the rest of the code will use.  Build it ourselves
#  to stop it from going to the filesystem.
mixKeystore._mixKeyStore = mixKeystore.MixKeyStore()

fk1 = open('key1.seckey', 'r')
mixKeystore._mixKeyStore.addKey(fk1.readlines(), "key1")
fk1.close()

fk2 = open('key2.seckey', 'r')
mixKeystore._mixKeyStore.addKey(fk2.readlines(), "key2")
fk2.close()

fk3 = open('key3.seckey', 'r')
mixKeystore._mixKeyStore.addKey(fk3.readlines(), "key3")
fk3.close()

#Open the Message
fm = open('message.msg', 'r')
msg1_lines = fm.readlines()
fm.close()

# ========================================================================
print "Client sends message with a Path of Node1,Node2,Node3"
print "  by pure luck (or unluck) Nodes 1 and 3 are attacker-controlled"
# ========================================================================
print "=" * 70
print "Received Message on Node 1, processing..."
#Process the message
msg1 = mixMessage.MixMessage(msg1_lines)

#Decrypt the Message As Node 1
msg1.decode()

#Display the Decrypted & Decoded Intermediate Message

print "Message recieved by Node 1, decrypted, and decoded:"
msg1.pprint()

#Create the message that will be sent to the second node
msg2_lines = msg1.deliveryBody()

if DoTaggingAttack:
    print "+" * 70
    print "Performing Tagging Attack"
    print "+" * 70
    #We want to flip the 240th byte of the second Mix Header
    #First seperate the message into it's components:
    headerIndex = msg2_lines.index("-----BEGIN REMAILER MESSAGE-----")
    lengthIndex = headerIndex + len("-----BEGIN REMAILER MESSAGE-----") + 1
    digestIndex = lengthIndex + len("20480") + 1
    dataIndex = digestIndex + len(base64.b64encode(hashlib.md5("").digest())) + 1
    footIndex = msg2_lines.index("-----END REMAILER MESSAGE-----")
    
    #Isolate the data
    tampereddata = msg2_lines[dataIndex:footIndex].replace("\n", "")
    tampereddata = base64.b64decode(tampereddata)
    
    #Corrupt the target byte (the actual mode of corruption is not significant)
    # 512 bytes to get past the first Mix Header, then 240 bytes beyond that
    targetByte = 240
    oldLength = len(tampereddata)
    if tampereddata[512 + targetByte] == '\x00':
        tampereddata = tampereddata[:512 + targetByte] + '\x01' + tampereddata[512 + targetByte + 1:]
    else:
        tampereddata = tampereddata[:512 + targetByte] + '\x00' + tampereddata[512 + targetByte + 1:]
    assert(oldLength == len(tampereddata))
     
    #Reassemble the message
    from mixMath import splitToNPerLine
    
    output  = "::" + "\n"
    output += "Remailer-Type: tagging-attack-demo\n"
    output += "\n"
    output += "-----BEGIN REMAILER MESSAGE-----" + "\n"
    output += "20480" + "\n"
    output += base64.b64encode(hashlib.md5(tampereddata).digest()) + "\n"
    tampereddata = base64.b64encode(tampereddata)
    output += splitToNPerLine(tampereddata) + "\n"
    output += "-----END REMAILER MESSAGE-----" + "\n"
    
    msg2_lines = output
    
print "Sending Message on to Node 2..."
# ========================================================================
print "=" * 70
print "Received Message on Node 2, processing..."
#Process the message
msg2 = mixMessage.MixMessage(msg2_lines)

#Decrypt the Message As Node 2
msg2.decode()

#Display the Decrypted & Decoded Intermediate Message
print "Message recieved by Node 2, decrypted, and decoded:"
msg2.pprint()

#Create the message that will be sent to the second node
msg3_lines = msg2.deliveryBody()

print "Sending Message on to Node 3..."
# ========================================================================
print "=" * 70
print "Received Message on Node 3, processing..."
#Process the message
msg3 = mixMessage.MixMessage(msg3_lines)

#Decrypt the Message As Node 3
try:
    msg3.decode()
except Exception, e:
    print "+" * 70
    print "Caught a Decoding Exception! Continuing Anyway..."
    
    msg3.decode(ignoreDigestErrors=True)
    
    firstHeader = msg3.Headers[0]
    actualDigest = hashlib.md5( firstHeader.EncHeader_Decrypted[0:firstHeader.DecryptedHeader.byteIndex] ).digest()
    observedDigest = firstHeader.DecryptedHeader.Digest
    print "Actual Digest  ", binascii.hexlify(actualDigest)
    print "Included Digest", binascii.hexlify(observedDigest)
    print "                |______________||______________|"
    print "                     Matches       Corrupted   "
    print "+" * 70
        

#Display the Decrypted & Decoded Intermediate Message
print "Message recieved by Node 3, decrypted, and decoded:"
msg3.pprint()