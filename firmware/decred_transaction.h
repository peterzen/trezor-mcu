/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2017 Peter Banik <peter@froggle.org>
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


#ifndef __DECRED_TRANSACTION_H__
#define __DECRED_TRANSACTION_H__

#include "transaction.h"
#include "blake256.h"


typedef struct {
	uint32_t inputs_len;
	uint32_t outputs_len;

	uint32_t version;
  uint32_t lock_time;
	uint32_t expiry;

	bool add_hash_type, is_segwit;

	uint32_t have_inputs;
	uint32_t have_outputs;

	uint32_t extra_data_len;
	uint32_t extra_data_received;

	uint32_t size;

	state256 ctx;
} DecredTxStruct;


void decred_tx_init(DecredTxStruct *tx, uint32_t inputs_len, uint32_t outputs_len, uint32_t version, uint32_t lock_time, uint32_t extra_data_len, bool add_hash_type);
void decred_tx_hash_final(DecredTxStruct *t, uint8_t *hash, bool reverse);

uint32_t decred_tx_prevout_hash(state256 *ctx, const DecredTxInType *input);
uint32_t decred_tx_script_hash(state256 *ctx, uint32_t size, const uint8_t *data);
uint32_t decred_tx_sequence_hash(state256 *ctx, const DecredTxInType *input);
uint32_t decred_tx_output_hash(state256 *ctx, const TxOutputBinType *output);
uint32_t decred_tx_serialize_script(uint32_t size, const uint8_t *data, uint8_t *out);

uint32_t decred_tx_serialize_footer(DecredTxStruct *tx, uint8_t *out);
uint32_t decred_tx_serialize_input(DecredTxStruct *tx, const DecredTxInType *input, uint8_t *out);
uint32_t decred_tx_serialize_output(DecredTxStruct *tx, const TxOutputBinType *output, uint8_t *out);

uint32_t decred_tx_serialize_header_hash(DecredTxStruct *tx);
uint32_t decred_tx_serialize_input_hash(DecredTxStruct *tx, const DecredTxInType *input);
uint32_t decred_tx_serialize_output_hash(DecredTxStruct *tx, const TxOutputBinType *output);
uint32_t decred_tx_serialize_extra_data_hash(DecredTxStruct *tx, const uint8_t *data, uint32_t datalen);


bool decred_compute_address(const CoinType *coin,
					 InputScriptType script_type,
					 const HDNode *node,
					 bool has_multisig, const MultisigRedeemScriptType *multisig,
					 char address[MAX_ADDR_SIZE]);

int decred_compile_output(const CoinType *coin, const HDNode *root, DecredTxOutType *in, TxOutputBinType *out, bool needs_confirm);
uint32_t decred_compile_script_sig(uint32_t address_type, const uint8_t *pubkeyhash, uint8_t *out);
uint32_t decred_compile_script_multisig(const MultisigRedeemScriptType *multisig, uint8_t *out);
uint32_t decred_compile_script_multisig_hash(const MultisigRedeemScriptType *multisig, uint8_t *hash);
uint32_t decred_serialize_script_sig(const uint8_t *signature, uint32_t signature_len, const uint8_t *pubkey, uint32_t pubkey_len, uint8_t *out);
uint32_t decred_serialize_script_multisig(const MultisigRedeemScriptType *multisig, uint8_t *out);



#endif
