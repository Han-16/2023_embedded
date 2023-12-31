#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
typedef unsigned char U8;
typedef unsigned int U32;
#define BYTES 16
#define BITS 128
int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b)
{
	//error
	if(b_r==NULL || b_a == NULL || b_b == NULL) 
		return 0;
	//bytes = bits / 8
	int i, bytes = bits >> 3;
	//calloc for type casting(BIGNUM to U8)
	U8 *r = (U8*)calloc(bytes,sizeof(U8));
	U8 *a = (U8*)calloc(bytes,sizeof(U8));
	U8 *b = (U8*)calloc(bytes,sizeof(U8));
	//BN_num_bytes(a) : return a's bytes 
	int byte_a = BN_num_bytes(b_a);
	int byte_b = BN_num_bytes(b_b);
	//difference between A and B
	int dif = abs(byte_a-byte_b);
	//minimum
	int byte_min = (byte_a < byte_b)? byte_a : byte_b;
	//type casting(BIGNUM to U8)
	BN_bn2bin(b_a,a);
	BN_bn2bin(b_b,b);
	//xor compute
	for(i=1;i<=byte_min;i++)
		r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
	for(i=1;i<=dif;i++)
		r[bytes - byte_min - i] = (byte_a>byte_b)? a[dif-i] : b[dif-i];
	//type casting(U8 to BIGNUM)
	BN_bin2bn(r,bytes,b_r);
	//Free memory
	free(a);
	free(b);
	free(r);
	return 1;//correct
}
int Gen(AES_KEY *enckey, int bits)
{
	if (enckey == NULL || bits <= 0) return 0;
	int bytes = bits >> 3;

	//*** write your code from here

	//choose uniform BN key

	//type casting BN key -> U8(binary) key

	//AES encrpytion key setting

	//*** end

	return 1;

}
U8 ** Enc(AES_KEY *k, int bits, U8 *m)
{
	int i, bytes = bits >> 3;
	U8 **c = (U8 **)calloc(2, sizeof(U8*)); // C = [r, F_k(r)]
	for (i = 0; i < 2; i++)
		c[i] = (U8 *)calloc(bytes, sizeof(U8));

	//*** write your code from here

	//choose uniform BN r
    
	
    //print BN r
	
    //setting C1

	//AES Encryption F_k(r)
	
	//type casting U8 F_k(r)-> BN F_k(r)    for F_k(r) xor m
	
    //print F_k(r)

	//type casting U8 m -> BN m       		for F_k(r) xor m

	//C2 = F_k(r) xor m
	
    //setting C2

	//*** end

	return c;
}
U8 *Dec(AES_KEY *k, int bits, U8 **C)
{
	int bytes = bits >> 3;
	U8 *M = (U8*)calloc(bytes, sizeof(U8));

	//*** write your code from here

    //compute F_k(C1)
    
    //type casting U8 F_k(C1) -> BN F_k(C1)       for  F_k(C1) xor C2
    
	//print F_k(C1)

    //type casting U8 C[1] -> BN C2                for  F_k(C1) xor C2
    
	//compute F_k(C1) xor C2 = m   and   type casting  BN m -> U8 M

	//*** end

	return M;
}
int main(int argc, char* argv[]) {
	int i;
	AES_KEY enckey; // AES encryption key
	U8 *m = (U8*)"CPA-secure";
	U8 *dec = (U8*)calloc(BYTES,sizeof(U8));
	
	Gen(&enckey,BITS);
	U8 **c = Enc(&enckey,BITS,m);
	U8 *d_m = Dec(&enckey,BITS,c);
	
	printf("C1 : ");
	for(i=0;i<BYTES;i++)
		printf("%02X",c[0][i]);
	printf("\n");
	printf("C2 : ");
	for(i=0;i<BYTES;i++)
		printf("%02X",c[1][i]);
	printf("\n");
	printf("Dec : %s\n", d_m);
	
	free(c[0]);
	free(c[1]);
	free(c);
	return 0;
}