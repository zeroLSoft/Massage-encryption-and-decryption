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
import random

def encrypt(sentence,s):
    encoded = blockConverter(sentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    B = (B + s[0])%modulo
    D = (D + s[1])%modulo 
    for i in range(1,r+1):
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        tmod=t%32
        umod=u%32
        A = (ROL(A^t,umod,32) + s[2*i])%modulo 
        C = (ROL(C^u,tmod,32) + s[2*i+ 1])%modulo
        (A, B, C, D)  =  (B, C, D, A)
    A = (A + s[2*r + 2])%modulo 
    C = (C + s[2*r + 3])%modulo
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    return orgi,cipher

#rc6 decription
def decrypt(esentence,s):
    encoded = blockConverter(esentence)
    enlength = len(encoded)
    A = int(encoded[0],2)
    B = int(encoded[1],2)
    C = int(encoded[2],2)
    D = int(encoded[3],2)
    cipher = []
    cipher.append(A)
    cipher.append(B)
    cipher.append(C)
    cipher.append(D)
    r=12
    w=32
    modulo = 2**32
    lgw = 5
    C = (C - s[2*r+3])%modulo
    A = (A - s[2*r+2])%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo 
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)  
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t) 
    D = (D - s[1])%modulo 
    B = (B - s[0])%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)
    return cipher,orgi