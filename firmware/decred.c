
/*
 * Copyright (c) 2017 Peter Banik
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */



#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <bsd/string.h>

#include "sha2.h"
#include "rand.h"

#include "decred.h"
#include "decred_pgpwordlist.h"


// Returns the checksum byte used at the end of the seed mnemonic
// encoding.  The "checksum" is the first byte of the double SHA256.
static uint8_t pgp_checksum_byte(const uint8_t *data, uint8_t len)
{
	uint8_t intermediate_hash[SHA256_DIGEST_LENGTH + 1];
	uint8_t final_hash[SHA256_DIGEST_LENGTH + 1];
	sha256_Raw(data, len, intermediate_hash);
	sha256_Raw(intermediate_hash, SHA256_DIGEST_LENGTH, final_hash);
	return final_hash[0];
}


const char *decred_seed_to_wordlist(const uint8_t *data, int seed_len){

  uint8_t checksum = pgp_checksum_byte(data, seed_len);
  const char *checksum_word = pgp_byte_to_mnemonic(checksum, seed_len);
  char *wordlist = pgp_mnemonic_from_data(data, seed_len);

  int word_len = strlen(checksum_word);
  char *p = wordlist + strlen(wordlist);
  *p++ = ' ';
  memcpy(p, checksum_word, word_len);

  return wordlist;
}




char *decred_generate_seed(int strength)
{
	if (strength % 32 || strength < 128 || strength > 256) {
		return 0;
	}
	uint8_t data[32];
	random_buffer(data, 32);
	return pgp_mnemonic_from_data(data, strength / 8);
}
