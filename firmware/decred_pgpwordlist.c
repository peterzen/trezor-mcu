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

#include "bip39.h"

#include "decred_pgpwordlist_english.h"
#include "decred_pgpwordlist.h"


// Returns the PGP word list encoding of b when found at index.
const char *pgp_byte_to_mnemonic(uint8_t byte, uint16_t index){
	uint16_t bb = (uint16_t)byte * 2;
	if(index % 2){
		++bb;
	}
	return pgpwordlist[bb];
}


char *pgp_mnemonic_from_data(const uint8_t *data, int seed_len)
{

	if (seed_len < MIN_SEED_LENGTH || seed_len > MAX_SEED_LENGTH) {
		return 0;
	}

	int i;
	int word_len;
	static char mnemonics[WORDLIST_MAX_LENGTH];
	const char *word;
	char *pos = mnemonics;

	for (i = 0; i < seed_len; i++) {
		word = pgp_byte_to_mnemonic(data[i], i);
		word_len = strlen(word);
		memcpy(pos, word, word_len);
		pos += word_len;
		if(i < (seed_len - 1)) {
			*pos++ = ' ';
		}
	}

	// uint8_t checksum = pgp_checksum_byte(data, seed_len);
	// word = pgp_byte_to_mnemonic(checksum, seed_len);
	// word_len = strlen(word);
	// memcpy(pos, word, word_len);
	// pos += word_len;

	*pos = 0;

	return mnemonics;
}



static int get_word_index(const char *word)
{
	for(uint16_t i = 0; pgpwordlist[i]; i++){
		if(strcasecmp(pgpwordlist[i], word) == 0){
			// printf("+ strcasecmp: %s == %s\t%d\n", pgpwordlist[i], word, i);
			return i;
		}
	}
	return -1;
}

int pgp_mnemonic_to_seed(const char *mnemonics, uint8_t seed[MAX_SEED_LENGTH])
{
	char mnemonic_tokens[WORDLIST_MAX_LENGTH];
	int byte, idx;

	strncpy(mnemonic_tokens, mnemonics, WORDLIST_MAX_LENGTH);
	memset(seed, 0, MAX_SEED_LENGTH);

	char *tok = strtok(mnemonic_tokens, " ");

	for(idx = 0; tok; ) {
		if(strlen(tok) == 0){
			continue;
		}
		byte = get_word_index(tok);
		if(byte == -1){
			fprintf(stderr, "word %s is not in the PGP word list\n", tok);
			return -1;
		}
		if((int)(byte % 2) != (idx % 2)){
			fprintf(stderr, "word %s is not valid at position %d\n", tok, idx);
			return -2;
		}
		seed[idx] = (uint8_t)(byte/2);
		tok = strtok(NULL, " ");
		idx++;
	}
	return 0;
}


const char * const *pgp_mnemonic_wordlist(void)
{
	return pgpwordlist;
}
