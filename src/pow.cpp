// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/system.h>

#include <consensus/consensus.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();
	
	// Genesis block
    if (pindexLast == nullptr)
        return nProofOfWorkLimit;
    if (pindexLast->nHeight+1 == params.BCDHeight)
    	return nProofOfWorkLimit;

    if (pindexLast->nHeight+1 == params.BCDHeight+1)
    	return UintToArith256(params.BCDBeginPowLimit).GetCompact();

    int height, interval;
    if (pindexLast->nHeight+1 > params.BCDHeight) {
    	height = pindexLast->nHeight+1 - params.BCDHeight;
    	interval = 72;
    }else{
    	height = pindexLast->nHeight+1;
    	interval = params.DifficultyAdjustmentInterval();
    }

    if (params.fPowNoRetargeting) {
        return pindexLast->nBits;
    }

    if (pindexLast->nHeight+1 < params.ZawyLWMAHeight) {
        return BCDGetNextWorkRequired(pindexLast, pblock, params, height, interval, nProofOfWorkLimit);
    }
    return LwmaGetNextWorkRequired(pindexLast, pblock, params);
}

unsigned int BCDGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params, int height, int interval, unsigned int nProofOfWorkLimit) {
    // Only change once per difficulty adjustment interval
    if (height % interval != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 72 minutes worth of blocks
    int nHeightFirst = pindexLast->nHeight - (interval-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    int limit, powTargetTimespan;
    if (pindexLast->nHeight+1 > params.BCDHeight) {
        powTargetTimespan = 72 * params.nPowTargetSpacing;
        limit = 2;
    }else{
        powTargetTimespan = params.nPowTargetTimespan;
        limit = 4;
    }

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    int64_t realActualTimespan = nActualTimespan;
    if (nActualTimespan < powTargetTimespan/limit)
        nActualTimespan = powTargetTimespan/limit;
    if (nActualTimespan > powTargetTimespan*limit)
        nActualTimespan = powTargetTimespan*limit;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    bnNew *= nActualTimespan;
    bnNew /= powTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    LogPrintf("GetNextWorkRequired RETARGET at nHeight = %d\n", pindexLast->nHeight+1);
    LogPrintf("params.nPowTargetTimespan = %d    nActualTimespan = %d    realActualTimespan = %d\n", powTargetTimespan, nActualTimespan, realActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}


unsigned int LwmaGetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params) {
    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2 * 10 minutes
    // then allow mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2) {
        return UintToArith256(params.BCDBeginPowLimit).GetCompact();
    }
    return LwmaCalculateNextWorkRequired(pindexLast, params);
}

unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const int height = pindexLast->nHeight + 1;
    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nZawyLwmaAveragingWindow;
    const int64_t k = params.nZawyLwmaAdjustedWeight;
    const int64_t dnorm = params.nZawyLwmaMinDenominator;
    const bool limit_st = params.bZawyLwmaSolvetimeLimitation;
    assert(height > N);

    arith_uint256 sum_target;
    int t = 0, j = 0;

    // Loop through N most recent blocks.
    for (int i = height - N; i < height; i++) {
        const CBlockIndex* block = pindexLast->GetAncestor(i);
        const CBlockIndex* block_Prev = block->GetAncestor(i - 1);
        int64_t solvetime = block->GetBlockTime() - block_Prev->GetBlockTime();

        if (limit_st && solvetime > 6 * T) {
            solvetime = 6 * T;
        }

        j++;
        t += solvetime * j;  // Weighted solvetime sum.

        // Target sum divided by a factor, (k N^2).
        // The factor is a part of the final equation. However we divide sum_target here to avoid
        // potential overflow.
        arith_uint256 target;
        target.SetCompact(block->nBits);
        sum_target += target / (k * N * N);
    }
    // Keep t reasonable in case strange solvetimes occurred.
    if (t < N * k / dnorm) {
        t = N * k / dnorm;
    }

    const arith_uint256 pow_limit = UintToArith256(params.BCDBeginPowLimit);
    arith_uint256 next_target = t * sum_target;
    if (next_target > pow_limit) {
        next_target = pow_limit;
    }

    return next_target.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
