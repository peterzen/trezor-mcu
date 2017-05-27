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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <check.h>
#include "check_mem.h"

#include "coins.h"
#include "curves.h"
#include "bip32.h"
#include "bip39.h"

#include "decred.h"
#include "decred_pgpwordlist.h"

#define FROMHEX_MAXLEN 256

#define VERSION_PUBLIC  0x0488b21e
#define VERSION_PRIVATE 0x0488ade4

void tohex(uint8_t * in, size_t insz, char *out, uint8_t outsz)
{
    uint8_t * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for(; pin < in+insz; pout +=2, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        if (pout + 2 - out > outsz){
            /* Better to truncate output string than overflow buffer */
            /* it would be still better to either return a status */
            /* or ensure the target buffer is large enough and it never happen */
            break;
        }
    }
    pout[-1] = 0;
}


const uint8_t *fromhex(const char *str)
{
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}



START_TEST(decred_test_features)
{
  const CoinType *coin;
  coin = coinByName("Decred");
  ck_assert_str_eq(coin->coin_name, "Decred");
  ck_assert_str_eq(coin->coin_shortcut, " DCR");
  ck_assert(coin->xpub_magic == 0x02fda926);
  ck_assert(coin->xprv_magic == 0x02fda4e8);
  ck_assert_int_eq(coin->address_type, 1855);
  ck_assert_int_eq(coin->address_type_p2sh, 1818);
}
END_TEST



START_TEST(decred_test_pgpwordlist)
{

	static const char *vectors[] = {
		"E58294F2E9A227486E8B061B31CC528FD7FA3F19",
		"topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless",
		"topmost Istanbul Pluto vagabond treadmill Pacific brackish dictator goldfish Medusa afflict bravado chatter revolver Dupont midsummer stopwatch whimsical cowbell bottomless",
		"00",

		"D1D464C004F00FB5C9A4C8D8E433E7FB7FF56256",
		"stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade",
		"stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade",
		"00",

		"aca149994b9c02e4a3c8d57e706895df06742ee097c29c43bafc64bbf5b99b9a",
		"   ribcage  outfielder DECKHAND     nebula dragnet   october accrue tradition ReFoRm   retrieval sterling insurgent guidance gravity preclude therapist afflict hydraulic buzzard tobacco preshrunk repellent python decimal shadow Wilmington flytrap publisher vapor proximate puppy newsletter   ",
		"ribcage outfielder deckhand nebula dragnet October accrue tradition reform retrieval sterling insurgent guidance gravity preclude therapist afflict hydraulic buzzard tobacco preshrunk repellent python decimal shadow Wilmington flytrap publisher vapor proximate puppy newsletter",
		"00",

		"aca149994b9c02e4a3c8d57e706895df06742ee097c29c43bafc64bbf5b99b9a",
		"   ribcage  outfielders DECKHAND     nebula dragnet   october accrue tradition ReFoRm   retrieval sterling insurgent guidance gravity preclude therapist afflict hydraulic buzzard tobacco preshrunk repellent python decimal shadow Wilmington flytrap publisher vapor proximate puppy newsletter   ",
		"ribcage outfielder deckhand nebula dragnet October accrue tradition reform retrieval sterling insurgent guidance gravity preclude therapist afflict hydraulic buzzard tobacco preshrunk repellent python decimal shadow Wilmington flytrap publisher vapor proximate puppy newsletter",
		"ffff",

		0,
		0,
		0,
		0,
	};
	uint8_t seed_output_1[MAX_SEED_LENGTH], seed_output_2[MAX_SEED_LENGTH];
	int retval_2;
	const char **seed, **word_list_in, **word_list_out, **retval_expected, *m;

	seed = vectors;
	word_list_in = vectors + 1;
	word_list_out = vectors + 2;
	retval_expected = vectors + 3;

	while(*seed && *word_list_in && *word_list_out && *retval_expected){
		m = pgp_mnemonic_from_data(fromhex(*seed), strlen(*seed)/2);
		pgp_mnemonic_to_seed(m, seed_output_1);
		retval_2 = pgp_mnemonic_to_seed(*word_list_in, seed_output_2);

		// printf("retval_1=%x\n\n", retval_1);
		// printf("retval_2=%x\n\n", retval_2);
		ck_assert_str_eq(m, *word_list_out);
		ck_assert_mem_eq(seed_output_1, fromhex(*seed), strlen(*seed)/2);

		uint8_t r = (uint8_t)retval_2;
		if(r == 0){
			ck_assert_mem_eq(seed_output_2, fromhex(*seed), strlen(*seed)/2);
		}
		else { // invalid word in supplied mnemonic
			ck_assert_mem_ne(seed_output_2, fromhex(*seed), strlen(*seed)/2);
		}
		ck_assert_int_eq(r, *(fromhex(*retval_expected)));

		seed += 4;
		word_list_in += 4;
		word_list_out += 4;
		retval_expected += 4;
	}

	// char outhex[64];

	// tohex(seed_output_1, 20, outhex, 40);
	// printf("seed_output_1=%s\n", outhex);


	// char mnemonics_2[] = "stairway souvenir flytrap recipe adrift upcoming artist positive spearhead Pandora spaniel stupendous tonic concurrent transit Wichita lockup visitor flagpole escapade";
	// uint8_t data_2[20] = fromhex("D1D464C004F00FB5C9A4C8D8E433E7FB7FF56256");

}
END_TEST

START_TEST(decred_test_wordlist_seed)
{
  const char *seed_in = "6ec70a6e996e374189a912267b331368a5d6ea57cc497bcf9a8c9bfc6a1f1770";

  const char *wordlist = decred_seed_to_wordlist(fromhex(seed_in), strlen(seed_in)/2);

  ck_assert_str_eq(wordlist, "goldfish retraction allow headwaters prowler headwaters clamshell decadence nightbird passenger atlas caretaker kickoff concurrent Aztec gravity reindeer speculate Trojan Eskimo spigot dinosaur kickoff Saturday pupil megaton puppy Wilmington Geiger businessman banjo hesitate snapshot");

}
END_TEST


// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("decred");
	TCase *tc;

  tc = tcase_create("decred_test_pgpwordlist");
	tcase_add_test(tc, decred_test_pgpwordlist);
	suite_add_tcase(s, tc);

  tc = tcase_create("decred_test_features");
	tcase_add_test(tc, decred_test_features);
	suite_add_tcase(s, tc);

  tc = tcase_create("decred_test_wordlist_seed");
	tcase_add_test(tc, decred_test_wordlist_seed);
	suite_add_tcase(s, tc);

	return s;
}


// run suite
int main(void)
{
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}
	return number_failed;
}
