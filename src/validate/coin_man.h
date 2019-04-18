// Copyright (c) 2019 The BCD Core developers


#ifndef BITCOINDIAMOND_COIN_MAN_H
#define BITCOINDIAMOND_COIN_MAN_H

#include <validate/validation_common.h>

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight);
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight);




#endif //BITCOINDIAMOND_COIN_MAN_H
