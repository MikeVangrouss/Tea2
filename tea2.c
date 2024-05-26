/*
/**********************************************************
   TEA2 - (Tiny Encryption Algorithm 2)
   
   TEA Feistel cipher by David Wheeler & Roger M. Needham
   TEA2 by Alexander PUKALL 2006
   
   128-bit block cipher (like AES) 256-bit key 128 rounds
   
   Code free for all, even for commercial software
   
   Compile with gcc : gcc tea2.c -o tea2
   
 **********************************************************/

/*
for TEA:
DELTA 0x9e3779b9 / sqr(5)-1 * 2^31 /
sqr(5)-1 = 1.2360679774997896964091736687313 
sqr(5)-1 * 2^31 =  2654435769.4972302964775847707926
2654435769 decimal = 9E3779B9 hexa
* 
for TEA2:
DELTA 0xFD258F8F3210C68 / sqr(5)-1 * 2^63 /
sqr(5)-1 = 1.2360679774997896964091736687313 
sqr(5)-1 * 2^63 = 11400714819323198485.9516105876220261392289212923904
1140071481932319848 decimal = FD258F8F3210C68 hexa 
  
*/

/**********************************************************
   Input values: 	k[4]	  256-bit key
                  v[2]    128-bit plaintext block
   Output values:	v[2]    128-bit ciphertext block 
 **********************************************************/

#include <stdint.h>
#include <stdio.h>

void encrypt(uint64_t* v, uint64_t* k)
{
uint64_t y=v[0],z=v[1],sum=0,             /* set up */
              delta=0xFD258F8F3210C68, n=64 ;  /* each iteration of the loop does two Feistel-cipher rounds */

while (n-->0)
{                                              /* basic cycle start*/
  sum += delta ;
  y += ((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1]) ;
  z += ((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3]) ;     /* end cycle */
}
v[0]=y ;
v[1]=z ;
}

void decrypt(uint64_t* v, uint64_t* k)
{
uint64_t y=v[0],z=v[1],sum=0xF4963E3CC8431A00,   /* set up; sum is (delta << 6) & 0xFFFFFFFFFFFFFFFF */
              delta=0xFD258F8F3210C68, n=64 ;  /* each iteration of the loop does two Feistel-cipher rounds */

while (n-->0)
{                                              /* basic cycle start*/
  z -= ((y<<4)+k[2]) ^ (y+sum) ^ ((y>>5)+k[3]) ;  
  y -= ((z<<4)+k[0]) ^ (z+sum) ^ ((z>>5)+k[1]) ;
  sum -= delta ;
 
}
v[0]=y ;
v[1]=z ;
}


void main()
{
  uint64_t v[2];
  uint64_t k[4];
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000000;
 
  printf("TEA2 by Alexander PUKALL 2006 \n 128-bit block 256-bit key 128 rounds\n");
  printf("Code can be freely use even for commercial software\n");
  printf("Based on TEA by David Wheeler & Roger M. Needham\n\n");
  
  printf("Encryption 1\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000000;
  v[1]=0x0000000000000001;
  
  printf("Encryption 2\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
  /* 256-bit key */
  k[0]=0x0000000000000000;
  k[1]=0x0000000000000000;
  k[2]=0x0000000000000000;
  k[3]=0x0000000000000001;
  
  /* 128-bit plaintext block */
  v[0]=0x0000000000000001;
  v[1]=0x0000000000000001;
  
  printf("Encryption 3\n");
  
  printf("Key: %0.16llX %0.16llX %0.16llX %0.16llX\n",k[0],k[1],k[2],k[3]);
  
  printf("Plaintext: %0.16llX %0.16llX\n",v[0],v[1]);
  
  encrypt(v,k);
  
  printf("Ciphertext:%0.16llX %0.16llX\n",v[0],v[1]);
  
  decrypt(v,k);
  
  printf("Decrypted: %0.16llX %0.16llX\n\n",v[0],v[1]);
  
   
}

/*

Encryption 1
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000000
Ciphertext:6EBC0771D933588A 020DA5B4625E1867
Decrypted: 0000000000000000 0000000000000000

Encryption 2
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000000 0000000000000001
Ciphertext:E093E1D3F05BA7DC 7C3A6E65D634AB0B
Decrypted: 0000000000000000 0000000000000001

Encryption 3
Key: 0000000000000000 0000000000000000 0000000000000000 0000000000000001
Plaintext: 0000000000000001 0000000000000001
Ciphertext:7A51A4E409512F7E FD07704C25408727
Decrypted: 0000000000000001 0000000000000001


*/

