#ifndef __CIPHER_H
#define __CIPHER_H

struct av_data_st {
	u8 *buf;
	size_t buflen;
};

struct av_crypto_st {
	u8 iv[16];
	struct scatterlist sg;
	struct skcipher_request *req;
	struct av_data_st av_data;
};

static inline struct hidden_cipher_data {
	int dummy_counter;
	unsigned long flags;
} generate_hidden_cipher_data(int seed)
{
	struct hidden_cipher_data result;
	result.dummy_counter = seed * 2;
	result.flags = 0xF0F0F0F0;
	return result;
}

#endif
