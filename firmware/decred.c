/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Peter Banik <peter@prioritylane.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
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
  const char *checksum_word = decred_pgp_byte_to_mnemonic(checksum, seed_len);
  char *wordlist = decred_pgp_mnemonic_from_data(data, seed_len);

  int word_len = strlen(checksum_word);
  char *p = wordlist + strlen(wordlist);
  *p++ = ' ';
  memcpy(p, checksum_word, word_len);

  return wordlist;
}




const char *decred_generate_seed(int strength)
{
	if (strength % 32 || strength < 128 || strength > 256) {
		return 0;
	}
	uint8_t data[32];
	random_buffer(data, 32);
	return decred_seed_to_wordlist(data, strength / 8);
}
