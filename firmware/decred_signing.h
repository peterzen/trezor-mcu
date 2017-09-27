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



#ifndef __DECRED_SIGNING_H__
#define __DECRED_SIGNING_H__

#include <stdint.h>
#include <stdbool.h>
#include "bip32.h"
#include "types.pb.h"

void decred_signing_init(uint32_t _inputs_count, uint32_t _outputs_count, const CoinType *_coin, const HDNode *_root, uint32_t _version, uint32_t _lock_time);
void decred_signing_abort(void);
void decred_signing_txack(DecredTransactionType *tx);
bool decred_check_change_bip32_path(const DecredTxOutType *toutput);
void decred_extract_input_bip32_path(const DecredTxInType *tinput);
bool decred_signing_sign_segwit_input(DecredTxInType *txinput);


#endif
