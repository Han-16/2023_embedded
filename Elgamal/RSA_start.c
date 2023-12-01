#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/dh.h>

typedef unsigned char U8;
typedef struct
{
	BIGNUM *d; 
	BIGNUM *x;
	BIGNUM *y;
}BN_dxy;

BN_dxy BN_dxy_new(const BIGNUM *d, const BIGNUM *x, const BIGNUM *y) {
	BN_dxy dxy;
	dxy.d = BN_new(); dxy.x = BN_new(); dxy.y = BN_new();
	if (d == NULL)
		return dxy;
	BN_copy(dxy.d, d);
	BN_copy(dxy.x, x);
	BN_copy(dxy.y, y);
	return dxy;
}

int BN_dxy_copy(BN_dxy * dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y)
{
	BN_copy(dxy->d, d);
	BN_copy(dxy->x, x);
	BN_copy(dxy->y, y);
}

void BN_dxy_free(BN_dxy * dxy)
{
	BN_free(dxy->d);
	BN_free(dxy->x);
	BN_free(dxy->y);
}

BN_dxy BN_Ext_Euclid(BIGNUM *a, BIGNUM *b)
{
    BN_dxy dxy;
    if (BN_is_zero(b))
    {
        dxy = BN_dxy_new(a, BN_value_one(), b);
        return dxy;
    }
    else
    {
        BIGNUM *q = BN_new();
        BIGNUM *r = BN_new();
        BIGNUM *temp1 = BN_new();
        BIGNUM *temp2 = BN_new();

        BN_CTX *ctx = BN_CTX_new();

        BIGNUM *d = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        BN_div(q, r, a, b, ctx);

        BN_dxy temp_dxy = BN_Ext_Euclid(b, r);

        BN_copy(d, temp_dxy.d);
        BN_copy(x, temp_dxy.y);
        BN_mul(temp1, q, temp_dxy.y, ctx);
        BN_sub(y, temp_dxy.x, temp1);

        BN_dxy_free(&temp_dxy);
        BN_free(q);
        BN_free(r);
        BN_free(temp1);
        BN_free(temp2);

        BN_CTX_free(ctx);

        dxy = BN_dxy_new(d, x, y);

        return dxy;
    }
}

BIGNUM *BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n)
{
    BIGNUM *result = BN_new();
    BIGNUM *temp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_one(result);

    int bits = BN_num_bits(a);

    for (int i = bits - 1; i >= 0; i--)
    {
        BN_mod_mul(result, result, result, n, ctx);

        if (BN_is_bit_set(a, i))
        {
            BN_mod_mul(result, result, x, n, ctx);
        }
    }

    BN_free(temp);
    BN_CTX_free(ctx);
    return result;
}

void RSA_setup(BIGNUM *pub_e, BIGNUM* pub_N, BIGNUM* priv)
{   
    BN_CTX *bn_ctx = BN_CTX_new();
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BN_dxy dxy; 
	BIGNUM *N = BN_new();
	BIGNUM *e = BN_new();
	BIGNUM *ord = BN_new(); // order of group
	BN_set_word(e, 3);

	while(1){
		BN_generate_prime_ex(p, 1024, 0, NULL, NULL, NULL);
		BN_generate_prime_ex(q, 1024, 0, NULL, NULL, NULL);

		if (BN_cmp(p, q) != 0)
            break;
	}

	/* code */
	
	printf("e\t : %s\n", BN_bn2hex(pub_e));
	printf("N\t : %s\n", BN_bn2hex(pub_N));
	printf("dxy.y\t : %s\n", BN_bn2hex(dxy.y));
	printf("dxy.x\t : %s\n", BN_bn2hex(dxy.x));
	printf("dxy.d\t : %s\n\n", BN_bn2hex(dxy.d));
}
U8 * RSA_enc(const U8 * msg, BIGNUM * pub_e, BIGNUM * pub_N)
{	
	BIGNUM *C = BN_new();
	BIGNUM *M = BN_new();
	BN_bin2bn(msg, strlen(msg), M);
	U8 * cipher;
	
	/* code */

	return cipher;
}
int RSA_dec(U8 *dec_msg, const BIGNUM *priv, const BIGNUM *pub_N, const U8 * cipher)
{
	BIGNUM * C = BN_new();
	BIGNUM * M = BN_new();

	/* code */
    
	return msg_len;
}
int main() {
	U8 *msg = "hello";
	BIGNUM * e = BN_new();
	BIGNUM * d = BN_new();
	BIGNUM * N = BN_new();
	RSA_setup(e, N, d);
	U8 * cipher = RSA_enc(msg, e, N);
	printf("Cipher text : %s\n", cipher);
	U8 dec_msg[1024] = { 0 };
	int dec_len = RSA_dec(dec_msg, d, N, cipher);
	printf("dec : %s\n", dec_msg);

	BN_free(e);
	BN_free(N);
	BN_free(d);
	return 0;
}
