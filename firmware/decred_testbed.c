

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bsd/string.h>

#include "coins.h"
#include "curves.h"
#include "bip32.h"
#include "bip39.h"

static uint8_t sessionSeed[64];

void get_root_node_callback(uint32_t iter, uint32_t total){
	// printf("get_root_node_callback() %d / %d\n", iter, total);
	if(iter > total){

	}
}

#define FROMHEX_MAXLEN 256

// #define VERSION_PUBLIC  0x0488b21e
// #define VERSION_PRIVATE 0x0488ade4

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

int main(void)
{
	const CoinType *coin;
	const char *curve = SECP256K1_NAME;
	size_t address_n_count = 1;
	uint32_t address_n[8] = {0,0,0,0,0};
	char *mnemonic = "color judge critic later casual harvest nurse two couch tonight lumber hat razor faint east";
//  "enlist Jamaica tycoon surrender sailboat Cherokee tissue fascinate ribcage letterhead seabird souvenir framework article showgirl inferno enlist backwater blowtorch paragraph watchword stupendous crumpled stethoscope tonic gadgetry glucose Montana necklace revolver orca Camelot slowdown"
	coin = coinByName("Decred");
	printf("Coin: %s\n", coin->coin_name);

	mnemonic_to_seed(mnemonic, "", sessionSeed, get_root_node_callback); // BIP-0039

	char seedHex[129];
	tohex(sessionSeed, 64, seedHex, sizeof(seedHex));
	printf("seed hex: %s\n", seedHex);

	static HDNode node;

	/*
	typedef struct {
		uint32_t depth;
		uint32_t child_num;
		uint8_t chain_code[32];
		uint8_t private_key[32];
		uint8_t public_key[33];
		const curve_info *curve;
	} HDNode;
	*/
	hdnode_from_seed(sessionSeed, 64, curve, &node);

	uint32_t fingerprint = 0;

	if (address_n_count) {
		fingerprint = hdnode_fingerprint(&node);
		hdnode_private_ckd(&node, address_n[address_n_count - 1]);
	}

	char private_key_hex[65];
	tohex(node.private_key, 32, private_key_hex, 65);
	printf("private_key1: %s\n", private_key_hex);

	int hdnode_private_ckd_out = hdnode_private_ckd(&node, 1);
	printf("hdnode_private_ckd_out: %d\n", hdnode_private_ckd_out);

	tohex(node.private_key, 32, private_key_hex, 65);
	printf("private_key2: %s\n", private_key_hex);


	char public_key_hex[67];
	tohex(node.public_key, 33, public_key_hex, 67);
	printf("public_key:   %s\n", public_key_hex);

	hdnode_fill_public_key(&node);

	char xprv[113];
	hdnode_serialize_private(&node, fingerprint, coin->xprv_magic, xprv, sizeof(xprv));
	printf("xprv: %s\n", xprv);

	char xpub[113];
	hdnode_serialize_public(&node, fingerprint, coin->xpub_magic, xpub, sizeof(xpub));
	printf("xpub: %s\n", xpub);

}
