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

#ifndef __PGPWORDLIST_H__
#define __PGPWORDLIST_H__


#define MAX_WORD_LENGTH 12
#define MAX_SEED_LENGTH 32
#define MIN_SEED_LENGTH 16
#define RECOMMENDED_SEED_LENGTH 32

// 1 additional word added for storing checksum
#define WORDLIST_MAX_LENGTH ((MAX_SEED_LENGTH + 1) * (MAX_WORD_LENGTH + 1) + 1)



const char *pgp_byte_to_mnemonic(uint8_t byte, uint16_t index);

char *pgp_mnemonic_from_data(const uint8_t *data, int len);

int pgp_mnemonic_to_seed(const char *mnemonics, uint8_t seed[MAX_SEED_LENGTH]);


const char * const *pgp_mnemonic_wordlist(void);


#endif
