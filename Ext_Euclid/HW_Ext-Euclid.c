#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>

void BN_scanf(BIGNUM *input) {
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}

void BN_printf(const BIGNUM *input) {
	char *c = BN_bn2dec(input);
	printf("%s ", c);
}
typedef struct {
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
void BN_dxy_copy(BN_dxy * dxy, BIGNUM *d, BIGNUM *x, BIGNUM *y)
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
BN_dxy BN_Ext_Euclid(BIGNUM* a, BIGNUM* b) {
    BN_dxy dxy;
    if (BN_is_zero(b)) {
        dxy = BN_dxy_new(a, BN_value_one(), b);
        return dxy;
    } else {
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

int main(int argc, char* argv[]) {
	BIGNUM *a, *b;
	BN_dxy dxy;
	a = BN_new(); b = BN_new();
	printf("a: "); BN_scanf(a);
	printf("b: "); BN_scanf(b);
	printf("result : \n");
	dxy = BN_Ext_Euclid(a, b);
	BN_printf(dxy.d); BN_printf(dxy.x); BN_printf(dxy.y);
	BN_dxy_free(&dxy);
	printf("\n");
	return 0;
}