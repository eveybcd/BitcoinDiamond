// Copyright (c) 2019 The BCD Core developers

#ifndef BITCOINDIAMOND_CVERIFYDB_H
#define BITCOINDIAMOND_CVERIFYDB_H

#include <bcd/validationcommon.h>


/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB {
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

#endif //BITCOINDIAMOND_CVERIFYDB_H
