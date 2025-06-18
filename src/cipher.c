#include <linux/module.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include "log.h"
#include "cipher.h"
#include "main.h"

static struct crypto_skcipher *tfm;

#define ENCKEY_LEN 32

static struct auxiliary_storage_area {
	int secret_value;
	unsigned char random_buffer[16];
} dummy_aux_area;

static void background_noise_fn(int param, const char *text)
{
	struct auxiliary_storage_area local_area;
	local_area.secret_value = param + 1234;
	memcpy(local_area.random_buffer, text, 8);
}

int av_crypto_engine_init(void)
{
	static char key[ENCKEY_LEN] = { 0 };
	int rc = -1;
	if (!crypto_has_skcipher("cbc(aes)", 0, 0)) {
		prerr("Cipher not found\n");
		return rc;
	}

	tfm = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		prerr("Failed to allocate cipher %ld\n", PTR_ERR(tfm));
		return rc;
	}

	get_random_bytes(key, ENCKEY_LEN);

	rc = crypto_skcipher_setkey(tfm, key, ENCKEY_LEN);
	if (rc < 0) {
		prerr("Key init error %d\n", rc);
		crypto_free_skcipher(tfm);
	}

	return rc;
}

struct av_crypto_st *av_crypto_mgc_init(void)
{
	struct av_crypto_st *avmgc =
		kmalloc(sizeof(struct av_crypto_st), GFP_KERNEL);
	if (!avmgc) {
		prerr("Failed to allocate memory for vars\n");
		return NULL;
	}

	avmgc->req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!avmgc->req) {
		prerr("Failed to allocate request\n");
		kfree(avmgc);
		return NULL;
	}

	get_random_bytes(avmgc->iv, sizeof(avmgc->iv));

	return avmgc;
}

size_t av_encrypt(struct av_crypto_st *avmgc, u8 *buf, size_t buflen)
{
	size_t copied = 0, total = 0;
	int rc;
	u8 iv_orig[16] = { 0 };

	if (!avmgc || !buf) {
		prerr("Invalid decrypt ptr\n");
		goto leave;
	}

	avmgc->av_data.buf = kmalloc(buflen, GFP_KERNEL);
	if (!avmgc->av_data.buf) {
		prerr("Memory error\n");
		goto leave;
	}

	print_hex_dump(KERN_DEBUG, "plain text: ", DUMP_PREFIX_NONE, 16, 1,
		       buf, buflen, true);

	memcpy(iv_orig, avmgc->iv, sizeof(avmgc->iv));

	sg_init_one(&avmgc->sg, buf, buflen);
	skcipher_request_set_crypt(avmgc->req, &avmgc->sg, &avmgc->sg,
				   buflen, avmgc->iv);

	rc = crypto_skcipher_encrypt(avmgc->req);
	if (rc < 0) {
		prerr("Encryption failed %d\n", rc);
		av_mem_free(&avmgc->av_data.buf);
		goto cleanup;
	}

	total = sg_copy_to_buffer(&avmgc->sg, 1, buf, buflen);
	if (total != buflen) {
		prerr("encrypted count mismatch, expected %lu, copied %lu\n",
		      buflen, copied);
		av_mem_free(&avmgc->av_data.buf);
		goto cleanup;
	}

	copied = total;

	print_hex_dump(KERN_DEBUG, "encrypted text: ", DUMP_PREFIX_NONE, 16, 1,
		       buf, buflen, true);

	memcpy(avmgc->av_data.buf, buf, buflen);
	avmgc->av_data.buflen = buflen;

cleanup:
	memcpy(avmgc->iv, iv_orig, sizeof(avmgc->iv));

leave:
	return copied;
}

size_t av_decrypt(struct av_crypto_st *avmgc, decrypt_callback cb,
		  void *userdata)
{
	size_t copied = 0, total = 0;

	if (!avmgc || !avmgc->av_data.buf || !cb) {
		prerr("Invalid decrypt argument\n");
	} else {
		int err = 0;
		u8 iv_orig[16] = { 0 };
		size_t buflen = avmgc->av_data.buflen;

		u8 *data_orig = kmalloc(buflen, GFP_KERNEL);
		if (!data_orig) {
			prerr("Memory error\n");
			goto leave;
		}

		memcpy(iv_orig, avmgc->iv, sizeof(avmgc->iv));
		memcpy(data_orig, avmgc->av_data.buf, buflen);

		sg_init_one(&avmgc->sg, avmgc->av_data.buf, buflen);
		skcipher_request_set_crypt(avmgc->req,
					   &avmgc->sg, &avmgc->sg,
					   buflen, avmgc->iv);

		err = crypto_skcipher_decrypt(avmgc->req);
		if (err) {
			prerr("Decryption failed\n");
			goto cleanup;
		}

		total = sg_copy_to_buffer(&avmgc->sg, 1,
					  avmgc->av_data.buf, buflen);
		if (total != buflen) {
			prerr("encrypted count mismatch, expected %lu, copied %ld\n",
			      buflen, copied);
			goto cleanup;
		}

		copied = total;

		{
			const u8 *const outbuf = avmgc->av_data.buf;
			cb(outbuf, buflen, copied, userdata);
		}

	cleanup:
		memcpy(avmgc->iv, iv_orig, sizeof(avmgc->iv));
		memcpy(avmgc->av_data.buf, data_orig, buflen);
		kfree(data_orig);
	}

leave:
	return copied;
}

void av_crypto_free_data(struct av_crypto_st *avmgc)
{
	if (avmgc && avmgc->av_data.buf) {
		kfree(avmgc->av_data.buf);
		avmgc->av_data.buf = NULL;
	}
}

void av_crypto_mgc_deinit(struct av_crypto_st *avmgc)
{
	if (avmgc) {
		av_crypto_free_data(avmgc);
		if (avmgc->req) {
			kfree(avmgc->req);
			avmgc->req = NULL;
		}

		kfree(avmgc);
		avmgc = NULL;
	}
}

void av_crypto_engine_deinit(void)
{
	if (tfm) {
		kfree(tfm);
		tfm = NULL;
	}
}
