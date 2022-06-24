import os
import sys
file_dir = os.path.dirname(__file__)
sys.path.append(file_dir)
from helpers import *
from elliptic import *
from sign import *
from verification import *
from key import *
from finitefield.finitefield import FiniteField
from RC6 import *
import random


def generateSecretKey(numBits):
   return int.from_bytes(os.urandom(numBits // 8), byteorder='big')


def sendDH(privateKey, generator, sendFunction):
   return sendFunction(privateKey * generator)


def receiveDH(privateKey, receiveFunction):
   return privateKey * receiveFunction()


def main():
    ####################### key exchange #################################
    aliceSecretKey = generateSecretKey(8)  #we chose 8 bit public key
    
    F = FiniteField(3851, 1) #p=3851
    
    keyGeneration("Alice",aliceSecretKey)
    
   # Totally insecure curve: y^2 = x^3 + 324x + 1287
    print("alice and bob use the curve:  y^2 = x^3 + 324x + 1287mod3851\n")
    print("Alice want to send encrypted text to bob\n")
    curve = EllipticCurve(a=F(324), b=F(1287))

    basePoint = Point(curve, F(920), F(303))
    
    
    print("Alice genarate secret key: ",aliceSecretKey)
    print("\n")
    

    alicePublicKey = sendDH(aliceSecretKey, basePoint, lambda x:x)
    print("Alice genarated public key: ",alicePublicKey)
    print("\n")
    
    send=str(alicePublicKey)
    
    file1 = open("msg.txt","w")
    file1.write(str(send))
    file1.close()
    print("Alice signature is:\n")
    c1,c2=sign("Alice",send)
    print("r: ",c1)
    print("\n")
    print("s: ",c2)
    print("\n")
    
    print("Alice sending public key(point) with signature to bob...............\n")
    print("Bob recive public key from alice\n")
    print("Bob cheking signature.........\n")
    
    if verification("Alice",c1,c2):
        print("signature confirmed")
    else:
        print("false signature program terminated/n")
        exit()
    
    bobSecretKey = generateSecretKey(8)
    keyGeneration("Bob",bobSecretKey)
    
    print("Bob genarate secret key:",bobSecretKey)
    print("\n")
    BobK = receiveDH(bobSecretKey, lambda: alicePublicKey)
    print("Bob genarate key to decrype the msg from alice: "+str(BobK.x.n))
    print("\n")
    
    bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x:x)
    print("Bob want to send public key to alice\n")
    print("Bob genarated public key: ",bobPublicKey)
    print("\n")
    
    send=""
    send=str(bobPublicKey)
    
    file1 = open("msg.txt","w")
    file1.write(str(send))
    
    print("Bob signature is:\n")
    c1,c2=sign("Bob",send)
    print("r: ",c1)
    print("\n")
    print("s: ",c2)
    print("\n")
    
    print("Bob sending public key(point) with signature to Alice...............\n")
    
    print("Alice recive public key from bob\n")
    print("Alice cheking signature.........\n")
    
    if verification("Bob",c1,c2):
        print("signature confirmed")
    else:
        print("false signature program terminated/n")
        exit(1)
    
    AliceK = receiveDH(aliceSecretKey, lambda: bobPublicKey)
    
    
    ############################### ENCRYPTION ############################
    
    key= str(AliceK.x.n)                    
    s = generateKey(key)
    key=str(BobK.x.n)                     
    s = generateKey(key)
    #sentence = 'I WORD IS A WORD'
    ori=sentence =input("Enter Sentence: ")
    
    #f = open("encrypted.txt","w",encoding="utf-8")
    esentence=""
    Bsentence=""
    while sentence:
      if len(sentence) <16:
        temp = sentence + " "*(16-len(sentence[:16]))
      temp = sentence[:16]
      if len(temp) <16:
          temp = temp + " "*(16-len(temp))
      print ("\nstring in work: "+temp )
      orgi,cipher = encrypt(temp,s)
      cr=""
      cr=deBlocker(cipher)
      esentence=esentence+cr
      print ("\nEncrypted msg: "+cr )
      file1 = open("msg.txt","w",encoding="utf-8")
      file1.write(cr)
      file1.close()
      
      sentence = sentence[16:]
  ############################### DECRYPTION ############################
    print("Full encripted sentence: "+esentence)
    c1,c2=sign("Alice",cr)
    print("Alice signature is:")
    c1,c2=sign("Alice",send)
    print("r: ",c1)
    print("s: ",c2)
    print("Send to bob")
    print("Bob cheking signature.........\n")
    
    if verification("Alice",c1,c2):
        print("signature confirmed")
    else:
        print("false signature program terminated/n")
        exit()
    
    ori=""
    
    print("Bob starting to DECRYPTION the msg.........\n")
    while esentence:
     if len(esentence) <16:
        temp = esentence + " "*(16-len(esentence[:16]))
     temp = esentence[:16]
     if len(temp) <16:
          temp = temp + " "*(16-len(temp))
      #print ("\nstring in work: "+temp+" len: " , len(temp) )
     cipher,orgi = decrypt(temp,s)
     sentence = deBlocker(orgi)
     ori=ori+sentence
     print ("\nstring in work: "+temp)
     print ("\nDecrypted msg: "+sentence)
     temp=""
     esentence = esentence[16:]
    
    
    print("\nFull Decrypted sentence: "+ori)
   
    
if __name__ == "__main__":
    main()
