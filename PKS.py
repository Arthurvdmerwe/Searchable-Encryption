import sys
from toolbox.pairinggroup import PairingGroup,pair
from toolbox.pairinggroup import  ZR,G1,G2,pair
from toolbox.hash_module import Hash, Exp
from toolbox.eccurve import *
import time


class PKS:

   def __init__(self, grpObj):

      self.group = grpObj
      self.h1 = Hash(pairingElement=self.group, htype='sha1')


   '''KeyGen(s): The security parameter s determines the size of the prime order p of the groups G_1and G_2. 
   The legal authority then also selects a random α ∈Z_p^* and a generator g of G_1. 
   The Output is a public key A_pub=[g,h=g^α] and a private key α. The public key is then distributed to the messaging server.'''
   def KeyGen(self):
       #select a random group element
      self.g = self.group.random(G1)
       #get the private key alpha
      self.priv = self.group.random(ZR)
       #calculate public key

      self.pub = (self.g, self.g ** self.priv)
      print ('KeyGen(s): Public Key: %s' % self.g ** self.priv)
      print('KeyGen(s): Private Key: %s' % self.priv)
      return self.pub

   ''' PKS(A_pub,W): Using the public key and a word W, 
      the messaging server computes a bilinear map t =e(H_1 (W),h^r )∈G_2 using the random oracle and a random r∈Z_p^*. 
      Then outputs a searchable encryption PKS(A_pub,W)=[g^r,H_2 (t)]. '''
   def PEKS(self, word):
      g, h = self.pub
      r = self.group.random(ZR)
      print('PKS(A_pub,W): Public Key: %s' % h)

      t = pair(self.group.hash(word, G2), h ** r)

      print('PKS(A_pub,W): MAP t: %s' % t)
      return (g ** r, t)

   '''	Trapdoor(A_priv,W): 
   The legal authority uses the random oracle and its private key to generate a trapdoor T_w=H_1 (W)^α∈G_1'''
   def Trapdoor(self, word):
      print('Trapdoor: %s for word: %s' % (self.group.hash(word, G1) ** self.priv, word))
      return self.group.hash(word, G1) ** self.priv




   '''	Test(A_pub,S,T_W): When the messaging server receives a 
   Test function from the legal authority as S=[A,B] it can test if H_2 (e(T_w,A))=B'''
   def Test(self, s, tw):
      a, b = s
      print(self.h1.hashToZn(str(pair(tw, a))))
      print(b)
      return self.h1.hashToZn(str(pair(tw, a))) == self.h1.hashToZn(str(b))


if __name__ == '__main__':
    group = PairingGroup('SS512')



    KEYWORD1 = "fishing"
    KEYWORD2 = "banana"

    time1 = time.time()
    pClient = PKS(group)
    time2 = time.time()
    print('%s function took %0.3f ms' % ("Initiating Pairing Groups", (time2 - time1) * 1000))

    time3 = time.time()
    pubKey = pClient.KeyGen()
    time4 = time.time()
    print('%s function took %0.3f ms' % ("Generating Keys", (time4 - time3) * 1000))

    time5 = time.time()
    p = pClient.PEKS(KEYWORD1)
    time6 = time.time()
    print('%s function took %0.3f ms' % ("Generating PKS", (time6 - time5) * 1000))

    time7 = time.time()
    t1 = pClient.Trapdoor(KEYWORD1)
    time8 = time.time()
    print('%s function took %0.3f ms' % ("Generating Trapdoor", (time8 - time7) * 100))

    t2 = pClient.Trapdoor(KEYWORD2)

    time9 = time.time()
    assert pClient.Test(p, t1)
    time10 = time.time()
    print('%s function took %0.3f ms' % ("Test ", (time10 - time9) * 100))

    print('------------------------------------------------')
    print(p)
    print(t1)
    print('------------------------------------------------')
    print(p)
    print(t2)
    print('------------------------------------------------')
    assert pClient.Test(p, t2)
    print('------------------------------------------------')