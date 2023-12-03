#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <json-c/json.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

typedef unsigned char U8;
static struct sockaddr_in client_addr;
static int client_fd, n, n2, state = 1;
static char recv_data[6000];
static char chat_data[6000];

#define PK2_new() BN_dxy_new(2)
#define PK2_free(a) BN_dxy_free(a, 2)
#define SK2_new() BN_dxy_new(2)
#define SK2_free(a) BN_dxy_free(a, 2)
#define CT2_new() BN_dxy_new(2)
#define CT2_free(a) BN_dxy_free(a, 2)
#define PK3_new() BN_dxy_new(3)
#define PK3_free(a) BN_dxy_free(a, 3)
#define SK3_new() BN_dxy_new(3)
#define SK3_free(a) BN_dxy_free(a, 3)
#define DXY_new() BN_dxy_new(3)
#define DXY_free(a) BN_dxy_free(a, 3)
#define SHA256_DIGEST_LENGTH 32
typedef struct
{
   union{
      BIGNUM *p;
      BIGNUM *d;
      BIGNUM *N;
      BIGNUM *C0;
   };
   union{
      BIGNUM *y;
      BIGNUM *key;
      BIGNUM *C1;
   };
   union{
      BIGNUM *g;
      BIGNUM *x;
   };
}BN_dxy;
typedef BN_dxy PK;
typedef BN_dxy SK;
typedef BN_dxy CT;

BN_dxy * BN_dxy_new(int element)
{
   BN_dxy * dxy = (BN_dxy *)calloc(1, sizeof(BN_dxy));
   if(element >=1)   dxy->d = BN_new(); 
   if(element >=2)   dxy->y = BN_new();
   if(element >=3)   dxy->x = BN_new();
   return dxy;
}
int BN_dxy_copy(const BN_dxy * dxy, const BIGNUM *d, const BIGNUM *x, const BIGNUM *y)
{
   BN_copy(dxy->d, d); 
   BN_copy(dxy->x, x); 
   BN_copy(dxy->y, y);
}
void BN_dxy_free(BN_dxy * dxy, int element)
{
   if(element >=1)   BN_free(dxy->d);
   if(element >=2)   BN_free(dxy->y);
   if(element >=3)   BN_free(dxy->x);
   free(dxy);
}
BN_dxy * BN_Ext_Euclid(const BIGNUM* a, const BIGNUM* b, BN_CTX * ctx){
   if (BN_is_zero(b)){
      BN_dxy * dxy;
      BIGNUM * one = BN_new();
      BN_one(one);
      dxy = DXY_new();
      BN_dxy_copy(dxy, a, one, b);
      BN_free(one);
      return dxy;
   }
   else{
      /*code*/
      BN_dxy *dxy;
      BIGNUM *div, *rem, *tmp;
      div = BN_new();
      rem = BN_new();
      tmp = BN_new();
      
      BN_div(div,rem,a,b,ctx);
      dxy = BN_Ext_Euclid(b,rem,ctx);
      
      BN_mul(tmp,div,dxy->y,ctx);
      BN_sub(tmp,dxy->x,tmp);
      
      BN_dxy_copy(dxy,dxy->d,dxy->y,tmp);
      BN_free(div);
      BN_free(rem);
      BN_free(tmp);
      
      return dxy;
   }
}
void BN_Square_Multi(BIGNUM * z,BIGNUM *x, BIGNUM *a, BIGNUM *n, BN_CTX * bn_ctx)
{
   //채워야할 부분
   /*code*/
   BIGNUM * r, * t;
   r = BN_new();
   t = BN_new();
   int k;
   int i;
   k = BN_num_bits(a);
   BN_one(z);
   for (i = k - 1; i >= 0; i--) {
      BN_sqr(r, z, bn_ctx);
      BN_mod(z, r, n, bn_ctx);
      if (BN_is_bit_set(a, i)) {
         BN_mul(t, z, x, bn_ctx);
         BN_mod(z, t, n, bn_ctx);
      }
   }
   BN_free(r);
   BN_free(t);
}
U8* RSA_enc(const U8 * msg, int msg_len, const PK *pub)
{	
	BIGNUM *C = BN_new();
	BIGNUM *M = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	BN_bin2bn(msg, msg_len, M);
	U8 * cipher;
	BN_Square_Multi(C,M, pub->key, pub->N,ctx);
	cipher = BN_bn2hex(C);

	BN_free(C);
	BN_free(M);
	printf("RSA_enc = %s\n",cipher);
	return cipher;
}
U8* RSA_dec(const U8 *cipher, int msg_len , const SK *priv)
{
	BIGNUM * C = BN_new();
	BIGNUM * M = BN_new();
	BN_CTX * ctx = BN_CTX_new();
	U8* dec_msg = (U8*)malloc(sizeof(U8*));
	BN_hex2bn(&C, cipher);
	BN_Square_Multi(M,C, priv->key, priv->N,ctx);
	BN_bn2bin(M, dec_msg);
	BN_free(C);
	BN_free(M);
	return dec_msg;
}
U8* RSA_sign(U8 *msg,int msg_len ,const SK *priv)
{
   /*code*/
   U8* sign;
   U8 digest[SHA256_DIGEST_LENGTH]={0};
   BIGNUM *bn_h = BN_new();
   BIGNUM *sig = BN_new();
   BN_CTX * ctx = BN_CTX_new();
   SHA256((unsigned char*)&msg,strlen(msg),(unsigned char*)&digest);
   char mdstring[SHA256_DIGEST_LENGTH*2+1];
   for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring[i*2],"%02X",(unsigned int)digest[i]);
   }
   printf("H(m) : %s\n",mdstring);
   BN_hex2bn(&bn_h,mdstring);
   BN_Square_Multi(sig,bn_h,priv->key,priv->N,ctx);
   sign = BN_bn2hex(sig);
   return sign;
}
int RSA_verify(U8 *msg,int msg_len, const U8 *sign, const PK *pub)
{
   /*code*/
   int result=0;
   U8 digest[SHA256_DIGEST_LENGTH]={0};
   U8* h1;
   int cnt=0;
   BIGNUM * bn_h = BN_new();
   BN_CTX *ctx = BN_CTX_new();
   BIGNUM * bn_sign = BN_new();
   BN_hex2bn(&bn_sign,sign);
   BN_Square_Multi(bn_h,bn_sign,pub->key,pub->N,ctx);
	
   h1 = BN_bn2hex(bn_h);
    SHA256_CTX hs = {0};
    SHA256_Init(&hs);
    SHA256_Update(&hs,msg,32);
    SHA256_Final(digest,&hs);
   char mdstring[SHA256_DIGEST_LENGTH*2+1];
   for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring[i*2],"%02X",(unsigned int)digest[i]);
   }
   for(int i=0;i<msg_len;i++){
      if(mdstring[i]==h1[i]) cnt++;
   }
   if(cnt == msg_len) result=1;
   else result=0;
	
   printf("H(m) : %s\n",mdstring);
   printf("H'   : %s\n",h1);
	BN_free(bn_h);
	BN_free(bn_sign);
	BN_CTX_free(ctx);

   return result;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Useage : ./client [IP] [PORT]\n");
        exit(0);
    }
    
    char *IP = argv[1];
    in_port_t PORT = atoi(argv[2]);

    client_fd = socket(PF_INET, SOCK_STREAM, 0);

    client_addr.sin_addr.s_addr = inet_addr(IP);
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(PORT);
   

   
    if (connect(client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1)
    {
        printf("Can't Connect\n");
        close(client_fd);
        return -1;
    }
   printf("connect\n");
   U8* nc = (U8*)malloc(sizeof(U8) *32);
   BIGNUM *NC = BN_new();
	BIGNUM *B_PMK = BN_new();
   BN_rand(NC,256,0,0);
	BN_rand(B_PMK,256,0,0);
   BN_bn2bin(NC,nc);
   json_object *object = json_object_new_object();
   json_object_object_add(object, "scheme", json_object_new_string("RSA_SCHEME"));
   json_object_object_add(object, "N", json_object_new_string(BN_bn2hex(NC)));
   const unsigned char * c_trans1 = json_object_to_json_string(object);
   if ((n = send(client_fd, c_trans1, strlen(c_trans1)+1, 0)) == -1){
      printf("send fail \n");
      return 0;
   }
   
   if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
         printf("recv error \n");
         return 0;
   }
   else printf("recv seccess \n");
   
   const U8* P_N;
   const U8* P_E;
   const U8* CA_N;
   const U8* CA_E;
   const U8* CERT;
	const U8* NS;
   json_object *token = json_tokener_parse(recv_data);   
   json_object *findP_N = json_object_new_object();
   json_object_object_get_ex(token, "P_N",&findP_N);
   P_N = json_object_get_string(findP_N);
   printf("P_N : %s \n",P_N);
   json_object *findP_E= json_object_new_object();
   json_object_object_get_ex(token, "P_E",&findP_E);
   P_E = json_object_get_string(findP_E);
   printf("P_E : %s \n",P_E);
   json_object *findCA_N= json_object_new_object();
   json_object_object_get_ex(token, "CA_N",&findCA_N);
   CA_N = json_object_get_string(findCA_N);
   printf("CA_N :%s \n",CA_N);
   json_object *findCA_E= json_object_new_object();
   json_object_object_get_ex(token, "CA_E",&findCA_E);
   CA_E = json_object_get_string(findCA_E);
   printf("CA_E :%s \n",CA_E);
   json_object *findCERT= json_object_new_object();
   json_object_object_get_ex(token, "CERT",&findCERT);
   CERT = json_object_get_string(findCERT);
   printf("CERT : %s \n",CERT);
	json_object *findNS= json_object_new_object();
   json_object_object_get_ex(token, "N",&findNS);
   NS = json_object_get_string(findNS);
   printf("NS : %s \n",NS);

    BIGNUM *B_P_N = BN_new();
    BIGNUM *B_P_E = BN_new();
    BN_hex2bn(&B_P_N,P_N);
    BN_hex2bn(&B_P_E,P_E);
    U8* p_n = (U8*)malloc(sizeof(U8)*32);
    U8* p_e = (U8*)malloc(sizeof(U8)*32);
    BN_bn2bin(B_P_N,p_n);
    BN_bn2bin(B_P_E,p_e);
    U8 digest[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs = {0};
    SHA256_Init(&hs);
    SHA256_Update(&hs,p_n,BN_num_bytes(B_P_N));
    SHA256_Update(&hs,p_e,BN_num_bytes(B_P_E));
    SHA256_Final(digest,&hs);
    char mdstring[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring[i*2],"%02X",(unsigned int)digest[i]);
    }
    printf("H    : %s\n",mdstring);
    BIGNUM *B_CA_E=BN_new();
    BIGNUM *B_CA_N=BN_new();
    BN_hex2bn(&B_CA_N,CA_N);
    BN_hex2bn(&B_CA_E,CA_E);
  PK *pub = PK2_new();
    BN_copy(pub->key,B_CA_E);
    BN_copy(pub->N,B_CA_N);
    if((n=RSA_verify(digest,32,CERT,pub)) == 1){
		printf("cert verify ok !\n");
    }
    else printf("cert verify fali !\n");
	free(p_n);
	free(p_e);
   U8* pmk = (U8*)malloc(sizeof(U8)*32);
   U8* ns = (U8*)malloc(sizeof(U8)*32);
   BIGNUM *B_NS = BN_new();
   BN_hex2bn(&B_NS,NS);
   BN_bn2bin(B_NS,ns);
    BN_bn2bin(B_PMK,pmk);
	printf("pmk : %s\n",BN_bn2hex(B_PMK));
   U8 digest1[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs1 = {0};
    SHA256_Init(&hs1);
    SHA256_Update(&hs1,pmk,BN_num_bytes(B_PMK));
    SHA256_Update(&hs1,nc,BN_num_bytes(NC));
   SHA256_Update(&hs1,ns,BN_num_bytes(B_NS));
    SHA256_Final(digest1,&hs1);
	char mdstring1[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring1[i*2],"%02X",(unsigned int)digest1[i]);
    }
    printf("MK    : %s\n",mdstring1);
   U8* C;

   C = RSA_enc(pmk,32,pub);
   json_object *object1 = json_object_new_object();
   json_object_object_add(object1, "C", json_object_new_string(C));
   const unsigned char * c_trans2 = json_object_to_json_string(object1);
   if ((n = send(client_fd, c_trans2, strlen(c_trans2)+1, 0)) == -1){
      printf("send fail \n");
      return 0;
   }
	int mdLen;
	U8* hmac = (U8*)malloc(sizeof(U8)*32);
	const EVP_MD* evpmd;
	evpmd=EVP_get_digestbyname("SHA256");
	HMAC_CTX *hctx = HMAC_CTX_new();
	HMAC_CTX_reset(hctx);	
	HMAC_Init_ex(hctx, digest1, SHA256_DIGEST_LENGTH, evpmd,0);
	HMAC_Update(hctx, c_trans1, strlen(c_trans1)); 	 	
	HMAC_Update(hctx, c_trans2, strlen(c_trans2)); 	 	
	HMAC_Final(hctx, hmac, &mdLen);
	BIGNUM *B_HMAC = BN_new();
	BN_bin2bn(hmac,32,B_HMAC);
	U8* HMAC1;
	HMAC1 = BN_bn2hex(B_HMAC);
   json_object *object2 = json_object_new_object();
   json_object_object_add(object2, "MAC", json_object_new_string(BN_bn2hex(B_HMAC)));
   const unsigned char * MAC = json_object_to_json_string(object2);
   if ((n = send(client_fd, MAC, strlen(MAC)+1, 0)) == -1){
      printf("send fail \n");
      return 0;
   }	
	printf("HMAC : %s\n",HMAC1);
	
	if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
         printf("recv error \n");
         return 0;
   }
   else printf("recv seccess \n");
	const U8* R_MAC;
   json_object *token1 = json_tokener_parse(recv_data);   
   json_object *findR_MAC = json_object_new_object();
   json_object_object_get_ex(token1, "MAC",&findR_MAC);
   R_MAC = json_object_get_string(findR_MAC);
   printf("R_MAC : %s \n",R_MAC);
	U8* s_mac = (U8*)malloc(sizeof(U8)*32);
	BIGNUM* B_S_MAC = BN_new();
	BN_hex2bn(&B_S_MAC,R_MAC);
	BN_bn2bin(B_S_MAC,s_mac);
	
	
	const unsigned char * s_trans1 = json_object_to_json_string(token);
	int mdLen1;
	U8* hmac1 = (U8*)malloc(sizeof(U8)*32);
	const EVP_MD* evpmd1;
	evpmd1=EVP_get_digestbyname("SHA256");
	HMAC_CTX *hctx1 = HMAC_CTX_new();
	HMAC_CTX_reset(hctx1);	
	HMAC_Init_ex(hctx1, digest1, SHA256_DIGEST_LENGTH, evpmd1,0);
	HMAC_Update(hctx1, s_trans1, strlen(s_trans1)); 	 		 	
	HMAC_Final(hctx1, hmac1, &mdLen1);
	BIGNUM *B_HMAC1= BN_new();
	BN_bin2bn(hmac1,32,B_HMAC1);
	U8* H_HMAC1;
	H_HMAC1 = BN_bn2hex(B_HMAC1);
	printf("MAC_  : %s\n",H_HMAC1);
	int cnt=0;
	for(int i=0; i<32; i++){
		if(hmac1[i] == s_mac[i]) cnt++;
	}
	if(cnt == 32){
		printf("mac Verification success\n\n");
	}
	else printf("mac Verification fail\n");

	char b_zero [1];
	b_zero[0] = 0;
	char b_one [1];
	b_one[0] = 1;
	char b_two [1];
	b_two [0] = 2;
	char b_three [1];
	b_three[0] = 3;

	
   U8 kc[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs2 = {0};
    SHA256_Init(&hs2);
	SHA256_Update(&hs2,b_zero,1);
    SHA256_Update(&hs2,digest1,32);
    SHA256_Final(kc,&hs2);
	char mdstring2[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring2[i*2],"%02X",(unsigned int)kc[i]);
    }
    printf("kc    : %s\n",mdstring2);
	
	U8 kc_[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs3 = {0};
    SHA256_Init(&hs3);
	SHA256_Update(&hs3,b_one,1);
    SHA256_Update(&hs3,digest1,32);
    SHA256_Final(kc_,&hs3);
	char mdstring3[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring3[i*2],"%02X",(unsigned int)kc_[i]);
    }
    printf("kc_   : %s\n",mdstring3);
	
	U8 ks[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs4 = {0};
    SHA256_Init(&hs4);
	SHA256_Update(&hs4,b_two,1);
    SHA256_Update(&hs4,digest1,32);
    SHA256_Final(ks,&hs4);
	char mdstring4[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring4[i*2],"%02X",(unsigned int)ks[i]);
    }
    printf("ks    : %s\n",mdstring4);
	
	U8 ks_[SHA256_DIGEST_LENGTH]={0};
    SHA256_CTX hs5 = {0};
    SHA256_Init(&hs5);
	SHA256_Update(&hs5,b_three,1);
    SHA256_Update(&hs5,digest1,32);
    SHA256_Final(ks_,&hs5);
	char mdstring5[SHA256_DIGEST_LENGTH*2+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
      sprintf(&mdstring5[i*2],"%02X",(unsigned int)ks_[i]);
    }
    printf("ks_   : %s\n",mdstring5);
	
	U8 MSG[] = "How are u?";
	U8* CT = (U8*)malloc(sizeof(U8)*16);
	AES_KEY s_enc_key;
	AES_set_encrypt_key(ks, 128, &s_enc_key);
	AES_encrypt(MSG,CT,&s_enc_key);
	BIGNUM* B_CT = BN_new();
	BN_bin2bn(CT,16,B_CT);
	U8* H_CT;
	H_CT = BN_bn2hex(B_CT);
	printf("CT : %s\n",H_CT);
	
	int mdLen2;
	U8* hmac2 = (U8*)malloc(sizeof(U8)*32);
	const EVP_MD* evpmd2;
	evpmd2=EVP_get_digestbyname("SHA256");
	HMAC_CTX *hctx2 = HMAC_CTX_new();
	HMAC_CTX_reset(hctx2);	
	HMAC_Init_ex(hctx2, ks_, SHA256_DIGEST_LENGTH, evpmd2,0);
	HMAC_Update(hctx2, CT, 16); 	 		 	
	HMAC_Final(hctx2, hmac2, &mdLen2);
	BIGNUM *B_H_CT = BN_new();
	BN_bin2bn(hmac2,32,B_H_CT);
	U8* H_H_CT;
	H_H_CT = BN_bn2hex(B_H_CT);
	printf("H_H_CT: %s\n",H_H_CT);

	json_object *object3 = json_object_new_object();
   json_object_object_add(object3, "CT", json_object_new_string(H_CT));
    json_object_object_add(object3, "MAC", json_object_new_string(H_H_CT));
	const unsigned char * CTC = json_object_to_json_string(object3);
   if ((n = send(client_fd, CTC, strlen(CTC)+1, 0)) == -1){
      printf("send fail \n");
      return 0;
   }	
	
	if((n = recv(client_fd, recv_data, sizeof(recv_data), 0))== -1){
         printf("recv error \n");
         return 0;
   }
   else printf("recv seccess \n");
	
	const U8* R_R_CT;
	const U8* R_R_MAC;
	json_object *token4 = json_tokener_parse(recv_data);   
   json_object *findCT = json_object_new_object();
   json_object_object_get_ex(token4, "CT",&findCT);
   R_R_CT = json_object_get_string(findCT);
   printf("R_CT : %s \n",R_R_CT); 
   json_object *findR_R_MAC = json_object_new_object();
   json_object_object_get_ex(token4, "MAC",&findR_R_MAC);
   R_R_MAC = json_object_get_string(findR_R_MAC);
   printf("R_MAC : %s \n",R_R_MAC);
	BIGNUM *B_R_R_CT = BN_new();
	U8* bin_CT = (U8*)malloc(sizeof(U8)*16);
	BN_hex2bn(&B_R_R_CT,R_R_CT);
	BN_bn2bin(B_R_R_CT,bin_CT);
	int mdLen3;
	U8* hmac3 = (U8*)malloc(sizeof(U8)*32);
	const EVP_MD* evpmd3;
	evpmd3=EVP_get_digestbyname("SHA256");
	HMAC_CTX *hctx3 = HMAC_CTX_new();
	HMAC_CTX_reset(hctx3);	
	HMAC_Init_ex(hctx3, kc_, SHA256_DIGEST_LENGTH, evpmd3,0);
	HMAC_Update(hctx3, bin_CT, 16); 	 		 	
	HMAC_Final(hctx3, hmac3, &mdLen3);
	BIGNUM *B_bin_CT = BN_new();
	BN_bin2bn(hmac3,32,B_bin_CT);
	U8* H_B_bin_CT;
	H_B_bin_CT = BN_bn2hex(B_bin_CT);
	printf("HMAC' : %s\n",H_B_bin_CT);
	int cnt1=0;
	for(int i=0;i<32;i++){
		if(H_B_bin_CT[i] == R_R_MAC[i]) cnt1++;
	}
	if(cnt1 == 32) {
		printf("Mac Verification Success\n");
		AES_KEY c_dec_key;
		AES_set_decrypt_key(kc, 128, &c_dec_key);
		U8* DEC_MSG =(U8*)malloc(sizeof(U8)*32);
		AES_decrypt(bin_CT,DEC_MSG,&c_dec_key);
		printf("%s\n",DEC_MSG);
	}
	else printf("Mac Verification fail\n");

	
    close(client_fd);
    return 0;
}