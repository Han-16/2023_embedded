#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/aes.h>


void Gen(BIGNUM *key, unsigned char *user_key, int n) {
	BN_rand(key, n, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
    BN_bn2bin(key, user_key);
}

void Enc(const unsigned char *user_key, const unsigned char *plaintext, unsigned char *ciphertext, AES_KEY *enc_key) {
	AES_encrypt(plaintext, ciphertext, enc_key);
}

void Dec(const unsigned char *user_key, const unsigned char *ciphertext, unsigned char *plaintext, AES_KEY *dec_key) {
    AES_decrypt(ciphertext, plaintext, dec_key);
}

int BN_xor(BIGNUM *b_r, int bits, const BIGNUM *b_a, const BIGNUM *b_b) {
	// error
	if (b_r == NULL || b_a == NULL || b_b == NULL)
		return 0;
	
	// bytes = bits / 8
	int i, bytes = bits >> 3;
	
	// calloc for type casting(BIGNUM to U8)
	U8 *r = (U8*)calloc(bytes, sizeof(U8));
	U8 *a = (U8*)calloc(bytes, sizeof(U8));
	U8 *b = (U8*)calloc(bytes, sizeof(U8));
	
	// BN_num_bytes(a) : return a's bytes
	int byte_a = BN_num_bytes(b_a);
	int byte_b = BN_num_bytes(b_b);
	
	// difference between A and BN_num_bytes
	int dif = abs(byte_a - byte_b);
	
	// minimum
	int byte_min = (byte_a < byte_b) ? byte_a : byte_b;
	
	// type casting(BIGNUM to U8)
	BN_bn2bin(b_a, a);
	BN_bn2bin(b_b, b);
	
	// xor compute
	for (i = 1; i <= byte_min; i++)
		r[bytes - i] = a[byte_a - i] ^ b[byte_b - i];
	
	for (i = 1; i <= dif; i++)
		r[bytes - byte_min - i] = (byte_a > byte_b) ? a[dif - i] : b[dif - i];
	
	// type casting(U8 to BIGNUM)
	BN_bin2bn(r, bytes, b_r);
	
	// Free memory
	free(a);
	free(b);
	free(r);
	
	return 1; // correct
}



int main(int argc, char* argv[]) {
	BIGNUM *key = BN_new();
	unsigned char user_key[16];
	int n = 128; // bit length
	
	AES_KEY enc_key; // AES encryption key
	AES_KEY dec_key; // AES decryption key
	
	// BN_rand(key, n, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY); // get random BN key
	// BN_bn2bin(key, user_key); // convert BN key to binary form
	Gen(key, user_key, n);
		
	AES_set_encrypt_key(user_key, n, &enc_key);
	AES_set_decrypt_key(user_key, n, &dec_key);
	
	unsigned char m[16] = "CPA-secure"; // key size = message size
	unsigned char enc[16];
	unsigned char dec[16];
	
	// AES_encrypt(m, enc, &enc_key); // Fk(r)
	// printf("enc: %s\n", enc);
	Enc(user_key, m, enc, &enc_key);
	printf("Fkr: %s\n", enc);
	
    
    printf("\n");
	
	
	// AES_decrypt(enc, dec, &dec_key); // Fk-1(r)
	// printf("dec: %s\n", dec);
	Dec(user_key, enc, dec, &dec_key); // 복호화 함수 호출
    printf("dec: %s\n", dec); // 복호화된 평문 출력

	
	BN_free(key);
	
	return 0;
}



