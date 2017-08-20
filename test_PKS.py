
from toolbox.pairinggroup import PairingGroup, G1
from PKS import PEKSClient, PEKSServer
from toolbox.integergroup import IntegerGroup



KEYWORD1 = "banaboo"
KEYWORD2 = "banana"


def main():

   group = PairingGroup('SS512', 512)

   #group.hash()

   pClient = PEKSClient(group)
   pubKey = pClient.KeyGen()

   pServer = PEKSServer(group, pubKey)

   p = pClient.PEKS(KEYWORD1)
   t1 = pClient.Trapdoor(KEYWORD1)
   t2 = pClient.Trapdoor(KEYWORD2)

   assert pServer.Test(p, t1)
   print('------------------------------------------------')
   print (p)
   print (t1)
   print ('------------------------------------------------')
   print (p)
   print (t2)
   print ('------------------------------------------------')
   assert   pServer.Test(p, t2)
   print ('------------------------------------------------')
if __name__ == '__main__':
   main()
