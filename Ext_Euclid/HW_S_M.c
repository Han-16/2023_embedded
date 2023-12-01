#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <ctype.h>
void BN_scanf(BIGNUM *input)
{
	int x;
	scanf("%d", &x);
	BN_set_word(input, x);
}
void BN_printf(const BIGNUM *input)
{
	char *c = BN_bn2dec(input);
	printf("%s ", c);
	free(c);
}
BIGNUM* BN_Square_Multi(BIGNUM *x, BIGNUM *a, BIGNUM *n) 
{
    BIGNUM *result = BN_new();
    BIGNUM *temp = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_one(result);

    int bits = BN_num_bits(a);
    
    for (int i = bits - 1; i >= 0; i--) {
        BN_mod_mul(result, result, result, n, ctx);

        if (BN_is_bit_set(a, i)) {
            BN_mod_mul(result, result, x, n, ctx);
        }
    }

    BN_free(temp);
    BN_CTX_free(ctx);
    return result;
}

int main(int argc, char* argv[]) {
	BIGNUM *x, *a, *n, *result;
	x = BN_new(); a = BN_new(); n = BN_new();
	printf("FAST Exponentiation (Square and Multiply)\n");
	printf("////////////  x^(a) mod n = ?   /////////////////\n");
	printf("x:"); BN_scanf(x);
	printf("a:"); BN_scanf(a);
	printf("n:"); BN_scanf(n);
	result = BN_Square_Multi(x, a, n);
	printf("result = "); BN_printf(result); printf("\n");
	BN_free(x); BN_free(a); BN_free(n); BN_free(result);
	return 0;
}
