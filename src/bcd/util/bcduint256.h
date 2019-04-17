// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BCDUINT256_H
#define BITCOIN_BCDUINT256_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>
#include <crypto/common.h>

#include <libdevcore/Common.h>
#include <libdevcore/CommonData.h>
#include <libdevcore/FixedHash.h>

inline dev::h256 uintToh256(const uint256& in)
{
    std::vector<unsigned char> vHashBlock;
    vHashBlock.assign(in.begin(), in.end());
    return dev::h256(vHashBlock);
}

inline uint256 h256Touint(const dev::h256& in)
{
	std::vector<unsigned char> vHashBlock = in.asBytes();
	return uint256(vHashBlock);
}

inline dev::u256 uintTou256(const uint256& in)
{
    std::vector<unsigned char> rawValue;
    rawValue.assign(in.begin(), in.end());
    return dev::fromBigEndian<dev::u256, dev::bytes>(rawValue);
}

inline uint256 u256Touint(const dev::u256& in)
{
    std::vector<unsigned char> rawValue(32, 0);
    dev::toBigEndian<dev::u256, dev::bytes>(in, rawValue);
	return uint256(rawValue);
}

#endif // BITCOIN_BCDUINT256_H
