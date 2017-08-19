
from toolbox.pairinggroup import PairingGroup, G1
from PKS import PEKSClient, PEKSServer
from toolbox.integergroup import IntegerGroup



KEYWORD1 = "coconut"
KEYWORD2 = "banana"


def main():

   group = PairingGroup('SS512', secparam=512)

   #group.hash()

   pClient = PEKSClient(group)
   pubKey = pClient.KeyGen()

   pServer = PEKSServer(group, pubKey)

   p = pClient.PEKS(KEYWORD1)
   t1 = pClient.Trapdoor(KEYWORD1)
   t2 = pClient.Trapdoor(KEYWORD2)

   assert pServer.Test(p, t1)

   print (p)
   print (t1)
   print ('------------------------------------------------')
   print (p)
   print (t2)
   print ('------------------------------------------------')
   assert not pServer.Test(p, t2)

if __name__ == '__main__':
   main()
