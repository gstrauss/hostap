/*
 * EAP server/peer: EAP-pwd shared routines
 * Copyright (c) 2010, Dan Harkins <dharkins@lounge.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "utils/const_time.h"
#include "common/dragonfly.h"
#include "crypto/sha256.h"
#include "crypto/crypto.h"
#include "eap_defs.h"
#include "eap_pwd_common.h"

#define MAX_ECC_PRIME_LEN 66


/* The random function H(x) = HMAC-SHA256(0^32, x) */
static int eap_pwd_hmac_sha256_vector(size_t num_elem, const u8 *addr[],
				      const size_t *len, u8 *mac)
{
	static u8 zeroes[SHA256_MAC_LEN];
	return hmac_sha256_vector(zeroes, sizeof(zeroes), num_elem, addr, len, mac);
}


/* a counter-based KDF based on NIST SP800-108 */
static int eap_pwd_kdf(const u8 *key, size_t keylen, const u8 *label,
		       size_t labellen, u8 *result, size_t resultbitlen)
{
	u16 i, ctr, L;
	size_t bytes = (resultbitlen + 7) / 8;
	const u8 *addr[4] = { result,   (u8 *) &i,    label, (u8 *) &L   };
	size_t lens[4] =    {      0, sizeof(u16), labellen, sizeof(u16) };

	WPA_PUT_BE16((u8 *)&L, resultbitlen);
	for (ctr = 1; bytes >= SHA256_MAC_LEN; bytes -= SHA256_MAC_LEN, ++ctr) {
		WPA_PUT_BE16((u8 *)&i, ctr);
		if (hmac_sha256_vector(key, keylen, 4, addr, lens, result))
			return -1;
		addr[0] = result;
		result += SHA256_MAC_LEN;
		lens[0] = SHA256_MAC_LEN; /*(include in subsequent rounds)*/
	}

	if (bytes) {
		u8 digest[SHA256_MAC_LEN];
		WPA_PUT_BE16((u8 *)&i, ctr);
		if (hmac_sha256_vector(key, keylen, 4, addr, lens, digest))
			return -1;
		os_memcpy(result, digest, bytes);
		result += bytes;
		forced_memzero(digest, sizeof(digest));
	}

	/* since we're expanding to a bit length, mask off the excess */
	if ((resultbitlen &= 0x7))
		result[-1] &= (u8)(0xff << (8 - resultbitlen));

	return 0;
}


EAP_PWD_group * get_eap_pwd_group(u16 num)
{
	EAP_PWD_group *grp;

	if (!dragonfly_suitable_group(num, 1)) {
		wpa_printf(MSG_INFO, "EAP-pwd: unsuitable group %u", num);
		return NULL;
	}
	grp = os_zalloc(sizeof(EAP_PWD_group));
	if (!grp)
		return NULL;
	grp->group = crypto_ec_init(num);
	if (!grp->group) {
		wpa_printf(MSG_INFO, "EAP-pwd: unable to create EC group");
		os_free(grp);
		return NULL;
	}

	grp->group_num = num;
	wpa_printf(MSG_INFO, "EAP-pwd: provisioned group %d", num);

	return grp;
}


/*
 * compute a "random" secret point on an elliptic curve based
 * on the password and identities.
 */
int compute_password_element(EAP_PWD_group *grp, u16 num,
			     const u8 *password, size_t password_len,
			     const u8 *id_server, size_t id_server_len,
			     const u8 *id_peer, size_t id_peer_len,
			     const u8 *token)
{
	int ret = 0, res;
	u8 ctr, found_ctr = 0, is_odd = 0;
	u8 found = 0; /* 0 (false) or 0xff (true) to be used as const_time_*
		       * mask */
	const size_t primebytelen = crypto_ec_prime_len(grp->group);
	const size_t primebitlen = crypto_ec_prime_len_bits(grp->group);
	const struct crypto_bignum *prime = crypto_ec_get_prime(grp->group);
	const u8 *addr[5] = { token, id_peer, id_server, password, &ctr };
	size_t lens[5] = { sizeof(u32), id_peer_len, id_server_len,
	                   password_len, sizeof(ctr) };
	u8 *prfbuf, *x_bin, *qr_bin, *qnr_bin, *prime_bin;
	u8 pwe_digest[SHA256_MAC_LEN+MAX_ECC_PRIME_LEN*5];
	x_bin      = pwe_digest+SHA256_MAC_LEN;
	prfbuf     = x_bin+primebytelen;
	qr_bin     = prfbuf+primebytelen;
	qnr_bin    = qr_bin+primebytelen;
	prime_bin  = qnr_bin+primebytelen;

	if (grp->pwe)
		return -1;

	if (crypto_bignum_to_bin(prime, prime_bin, primebytelen,
				 primebytelen) < 0)
		return -1;

	/* get a random quadratic residue and nonresidue */
	if (dragonfly_get_random_qr_qnr_bin(prime, primebytelen,
	                                    qr_bin, qnr_bin) < 0)
		return -1;

	os_memset(x_bin, 0, primebytelen); /*(init for constant time copying)*/
	ctr = 0;

	/*
	 * Run through the hunting-and-pecking loop 40 times to mask the time
	 * necessary to find PWE. The odds of PWE not being found in 40 loops is
	 * roughly 1 in 1 trillion.
	 */
	while (ctr < 40) {
		ctr++;

		/*
		 * compute counter-mode password value and stretch to prime
		 *    pwd-seed = H(token | peer-id | server-id | password |
		 *		   counter)
		 */
		if (eap_pwd_hmac_sha256_vector(5, addr, lens, pwe_digest))
			goto fail;

		is_odd = const_time_select_u8(
			found, is_odd, pwe_digest[SHA256_MAC_LEN - 1] & 0x01);
		if (eap_pwd_kdf(pwe_digest, SHA256_MAC_LEN,
				(u8 *) "EAP-pwd Hunting And Pecking",
				os_strlen("EAP-pwd Hunting And Pecking"),
				prfbuf, primebitlen) < 0)
			goto fail;
		if (primebitlen % 8)
			buf_shift_right(prfbuf, primebytelen,
					8 - primebitlen % 8);
		wpa_hexdump_key(MSG_DEBUG, "EAP-pwd: x_candidate",
				prfbuf, primebytelen);
		const_time_select_bin(found, x_bin, prfbuf, primebytelen,
				      x_bin);

		res = dragonfly_test_x(grp->group, prime_bin, primebytelen,
		                       qr_bin, qnr_bin, prfbuf);
		if (res < 0)
			goto fail;
		found_ctr = const_time_select_u8(found, found_ctr, ctr);
		found |= res;
	}
	if (found == 0) {
		wpa_printf(MSG_INFO,
			   "EAP-pwd: unable to find random point on curve for group %d, something's fishy",
			   num);
		goto fail;
	}

	grp->pwe = dragonfly_derive_point(grp->group, x_bin, prime,
	                                  primebytelen, is_odd);
	if (!grp->pwe) {
		wpa_printf(MSG_DEBUG, "EAP-pwd: Could not generate PWE");
		goto fail;
	}

	crypto_ec_point_debug_print(grp->group, grp->pwe, "EAP-pwd: PWE");

	/*
	 * If there's a solution to the equation then the point must be on the
	 * curve so why check again explicitly? OpenSSL code says this is
	 * required by X9.62. We're not X9.62 but it can't hurt just to be sure.
	 */
	if (!crypto_ec_point_is_on_curve(grp->group, grp->pwe)) {
		wpa_printf(MSG_INFO, "EAP-pwd: point is not on curve");
		goto fail;
	}

	wpa_printf(MSG_DEBUG, "EAP-pwd: found a PWE in %02d tries", found_ctr);

	if (0) {
 fail:
		crypto_ec_point_deinit(grp->pwe, 1);
		grp->pwe = NULL;
		ret = 1;
	}
	/* cleanliness and order.... */
	forced_memzero(pwe_digest, SHA256_MAC_LEN+primebytelen*4);
	return ret;
}


int compute_keys(EAP_PWD_group *grp, const struct crypto_bignum *k,
		 const struct crypto_bignum *peer_scalar,
		 const struct crypto_bignum *server_scalar,
		 const u8 *confirm_peer, const u8 *confirm_server,
		 const u32 *ciphersuite, u8 *msk, u8 *emsk, u8 *session_id)
{
	u8 mk[SHA256_MAC_LEN], *cruft;
	u8 msk_emsk[EAP_MSK_LEN + EAP_EMSK_LEN];
	size_t prime_len, order_len;
	const u8 *addr[3] = { (u8 *) ciphersuite, NULL, NULL };
	size_t lens[3] = { sizeof(u32), 0, 0 };

	prime_len = crypto_ec_prime_len(grp->group);
	order_len = crypto_ec_order_len(grp->group);

	cruft = os_malloc(prime_len*2);
	if (!cruft)
		return -1;
	addr[1] = cruft;
	addr[2] = cruft+prime_len;
	lens[1] = order_len;
	lens[2] = order_len;

	/*
	 * first compute the session-id = TypeCode | H(ciphersuite | scal_p |
	 *	scal_s)
	 */
	session_id[0] = EAP_TYPE_PWD;
	crypto_bignum_to_bin(peer_scalar, cruft, order_len, order_len);
	crypto_bignum_to_bin(server_scalar, cruft+prime_len, order_len, order_len);
	if (eap_pwd_hmac_sha256_vector(3, addr, lens, &session_id[1])) {
		os_free(cruft);
		return -1;
	}

	/* then compute MK = H(k | confirm-peer | confirm-server) */
	addr[0] = cruft;
	addr[1] = confirm_peer;
	addr[2] = confirm_server;
	lens[0] = prime_len;
	lens[1] = SHA256_MAC_LEN;
	lens[2] = SHA256_MAC_LEN;
	crypto_bignum_to_bin(k, cruft, prime_len, prime_len);
	if (eap_pwd_hmac_sha256_vector(3, addr, lens, mk)) {
		os_free(cruft);
		return -1;
	}
	os_free(cruft);

	/* stretch the mk with the session-id to get MSK | EMSK */
	if (eap_pwd_kdf(mk, SHA256_MAC_LEN,
			session_id, SHA256_MAC_LEN + 1,
			msk_emsk, (EAP_MSK_LEN + EAP_EMSK_LEN) * 8) < 0) {
		return -1;
	}

	os_memcpy(msk, msk_emsk, EAP_MSK_LEN);
	os_memcpy(emsk, msk_emsk + EAP_MSK_LEN, EAP_EMSK_LEN);

	return 1;
}


int compute_confirm(struct crypto_ec *group,
		    struct crypto_bignum *k,
		    struct crypto_ec_point *element1,
		    struct crypto_bignum *scalar1,
		    struct crypto_ec_point *element2,
		    struct crypto_bignum *scalar2,
		    u16 group_num,
		    u8 *confirm)
{
	const size_t prime_len = crypto_ec_prime_len(group);
	const size_t order_len = crypto_ec_order_len(group);
	const size_t cruft_len = prime_len + (prime_len * 2 + order_len) * 2 + 4;
	u8 *cruft = os_malloc(cruft_len);
	if (!cruft) {
		wpa_printf(MSG_INFO, "EAP-PWD: debug allocation fail");
		return -1;
	}
	u8 *bin_k           = cruft;
	u8 *bin_element1    = bin_k + prime_len;
	u8 *bin_scalar1     = bin_element1 + prime_len * 2;
	u8 *bin_element2    = bin_scalar1 + order_len;
	u8 *bin_scalar2     = bin_element2 + prime_len * 2;
	u8 *bin_ciphersuite = bin_scalar2 + order_len;
	int ret = -1;

	if (crypto_bignum_to_bin(k, bin_k, prime_len, prime_len) < 0)
		goto fin;

	/* element1: x, y */
	if (crypto_ec_point_to_bin(group, element1,
				   bin_element1, bin_element1+prime_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-PWD: confirm point assignment fail");
		goto fin;
	}

	/* scalar1 */
	if (crypto_bignum_to_bin(scalar1, bin_scalar1, order_len, order_len) < 0)
		goto fin;

	/* element2: x, y */
	if (crypto_ec_point_to_bin(group, element2,
				   bin_element2, bin_element2+prime_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-PWD: confirm point assignment fail");
		goto fin;
	}

	/* scalar2 */
	if (crypto_bignum_to_bin(scalar2, bin_scalar2, order_len, order_len) < 0)
		goto fin;

	/* ciphersuite: group | random_function | prf */
	group_num = htons(group_num);
	os_memcpy(bin_ciphersuite, &group_num, sizeof(u16));
	bin_ciphersuite[2] = EAP_PWD_DEFAULT_RAND_FUNC;
	bin_ciphersuite[3] = EAP_PWD_DEFAULT_PRF;

	const u8 *addr = cruft;
	size_t len = cruft_len;
	eap_pwd_hmac_sha256_vector(1, &addr, &len, confirm);

	ret = 0;
fin:
	bin_clear_free(cruft, cruft_len);
	return ret;
}


static int eap_pwd_element_coord_ok(const struct crypto_bignum *prime,
				    const u8 *buf, size_t len)
{
	struct crypto_bignum *val;
	int ok = 1;

	val = crypto_bignum_init_set(buf, len);
	if (!val || crypto_bignum_is_zero(val) ||
	    crypto_bignum_cmp(val, prime) >= 0)
		ok = 0;
	crypto_bignum_deinit(val, 0);
	return ok;
}


struct crypto_ec_point * eap_pwd_get_element(EAP_PWD_group *group,
					     const u8 *buf)
{
	struct crypto_ec_point *element;
	const struct crypto_bignum *prime;
	size_t prime_len;

	prime = crypto_ec_get_prime(group->group);
	prime_len = crypto_ec_prime_len(group->group);

	/* RFC 5931, 2.8.5.2.2: 0 < x,y < p */
	if (!eap_pwd_element_coord_ok(prime, buf, prime_len) ||
	    !eap_pwd_element_coord_ok(prime, buf + prime_len, prime_len)) {
		wpa_printf(MSG_INFO, "EAP-pwd: Invalid coordinate in element");
		return NULL;
	}

	element = crypto_ec_point_from_bin(group->group, buf);
	if (!element) {
		wpa_printf(MSG_INFO, "EAP-pwd: EC point from element failed");
		return NULL;
	}

	/* RFC 5931, 2.8.5.2.2: on curve and not the point at infinity */
	if (!crypto_ec_point_is_on_curve(group->group, element) ||
	    crypto_ec_point_is_at_infinity(group->group, element)) {
		wpa_printf(MSG_INFO, "EAP-pwd: Invalid element");
		goto fail;
	}

out:
	return element;
fail:
	crypto_ec_point_deinit(element, 0);
	element = NULL;
	goto out;
}


struct crypto_bignum * eap_pwd_get_scalar(EAP_PWD_group *group, const u8 *buf)
{
	struct crypto_bignum *scalar;
	const struct crypto_bignum *order;
	size_t order_len;

	order = crypto_ec_get_order(group->group);
	order_len = crypto_ec_order_len(group->group);

	/* RFC 5931, 2.8.5.2: 1 < scalar < r */
	scalar = crypto_bignum_init_set(buf, order_len);
	if (!scalar || crypto_bignum_is_zero(scalar) ||
	    crypto_bignum_is_one(scalar) ||
	    crypto_bignum_cmp(scalar, order) >= 0) {
		wpa_printf(MSG_INFO, "EAP-pwd: received scalar is invalid");
		crypto_bignum_deinit(scalar, 0);
		scalar = NULL;
	}

	return scalar;
}


int eap_pwd_get_rand_mask(EAP_PWD_group *group, struct crypto_bignum *_rand,
			  struct crypto_bignum *_mask,
			  struct crypto_bignum *scalar)
{
	return dragonfly_generate_scalar(crypto_ec_get_order(group->group),
					 _rand, _mask, scalar);
}
