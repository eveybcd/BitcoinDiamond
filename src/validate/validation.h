// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_H
#define BITCOIN_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <amount.h>
#include <coins.h>
#include <fs.h>
#include <protocol.h> // For CMessageHeader::MessageStartChars
#include <policy/feerate.h>
#include <script/script_error.h>
#include <sync.h>
#include <versionbits.h>
#include <algorithm>
#include <exception>
#include <map>
#include <memory>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

#include <atomic>

#include <validate/cverify_db.h>
#include <validate/chain_cache.h>
#include <validate/cchain_state.h>
#include <validate/coin_man.h>

class CBlockIndex;
class CBlockTreeDB;
class CChainParams;
class CCoinsViewDB;
class CInv;
class CConnman;
class CBlockPolicyEstimator;
class CTxMemPool;
class CValidationState;
struct ChainTxData;

struct PrecomputedTransactionData;
struct LockPoints;



extern CScript COINBASE_FLAGS;


extern std::atomic_bool g_is_mempool_loaded;

extern BlockMap& mapBlockIndex;
extern uint64_t nLastBlockTx;
extern uint64_t nLastBlockWeight;
extern const std::string strMessageMagic;



extern std::atomic_bool fImporting;


extern bool fIsBareMultisigStd;


/** Absolute maximum transaction fee (in satoshis) used by wallet and mempool (rejects high fee in sendrawtransaction) */
extern CAmount maxTxFee;
/** If the tip is older than this (in seconds), the node is considered to be in initial block download. */
extern int64_t nMaxTipAge;
extern bool fEnableReplacement;












/** Minimum blocks required to signal NODE_NETWORK_LIMITED */
static const unsigned int NODE_NETWORK_LIMITED_MIN_BLOCKS = 288;

static const signed int DEFAULT_CHECKBLOCKS = 6;
static const unsigned int DEFAULT_CHECKLEVEL = 3;

// Require that user allocate at least 550MB for block & undo files (blk???.dat and rev???.dat)
// At 1MB per block, 288 blocks = 288MB.
// Add 15% for Undo data = 331MB
// Add 20% for Orphan block rate = 397MB
// We want the low water mark after pruning to be at least 397 MB and since we prune in
// full block file chunks, we need the high water mark which triggers the prune to be
// one 128MB block file + added 15% undo data = 147MB greater for a total of 545MB
// Setting the target to > than 550MB will make it likely we can respect the target.
static const uint64_t MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 * 1024 * 1024;

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * May not be called in a
 * validationinterface callback.
 *
 * @param[in]   pblock  The block we want to process.
 * @param[in]   fForceProcessing Process this block even if unrequested; used for non-network block sources and whitelisted peers.
 * @param[out]  fNewBlock A boolean which is set to indicate if the block was first received via this call
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool* fNewBlock) LOCKS_EXCLUDED(cs_main);

/**
 * Process incoming block headers.
 *
 * May not be called in a
 * validationinterface callback.
 *
 * @param[in]  block The block headers themselves
 * @param[out] state This may be set to an Error state if any error occurred processing them
 * @param[in]  chainparams The params for the chain we want to connect to
 * @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
 * @param[out] first_invalid First header that fails validation, if one exists
 */
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& block, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex = nullptr, CBlockHeader* first_invalid = nullptr) LOCKS_EXCLUDED(cs_main);



/** Ensures we have a genesis block in the block tree, possibly writing one to disk. */
bool LoadGenesisBlock(const CChainParams& chainparams);
/** Load the block tree and coins database from disk,
 * initializing state if we're running with -reindex. */
bool LoadBlockIndex(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/** Update the chain tip based on database information. */
bool LoadChainTip(const CChainParams& chainparams);
/** Unload database information */
void UnloadBlockIndex();
/** Run an instance of the script checking thread */
void ThreadScriptCheck();

/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256& hash, CTransactionRef& tx, const Consensus::Params& params, uint256& hashBlock, bool fAllowSlow = false, CBlockIndex* blockIndex = nullptr);








/** Get the BIP9 state for a given deployment at the current tip. */
ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the numerical statistics for the BIP9 state for a given deployment at the current tip. */
BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos);

/** Get the block height at which the BIP9 deployment switched into the state for the block building on the current tip. */
int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos);



/**
 * Test whether the LockPoints height and time are still valid on the current chain
 */
bool TestLockPointValidity(const LockPoints* lp);



/** Initializes the script-execution cache */
void InitScriptExecutionCache();




/** Functions for validating blocks and updating the block tree */



/** Check a block is completely valid from start to finish (only works on top of our current best block) */
bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main);



/** When there are blocks in the active chain with missing data, rewind the chainstate and remove them from the block index */
bool RewindBlockIndex(const CChainParams& params);

/** Update uncommitted block structures (currently: only the witness reserved value). This is safe for submitted blocks. */
void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

/** Produce the necessary coinbase commitment for a block (modifies the hash, don't call for mined blocks). */
std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);



/** Replay blocks that aren't fully applied to the database. */
bool ReplayBlocks(const CChainParams& params, CCoinsView* view);


/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

/** Mark a block as precious and reorganize.
 *
 * May not be called in a
 * validationinterface callback.
 */
bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex) LOCKS_EXCLUDED(cs_main);

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Remove invalidity status from a block and its descendants. */
void ResetBlockFailureFlags(CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);



/** Global variable that points to the coins database (protected by cs_main) */
extern std::unique_ptr<CCoinsViewDB> pcoinsdbview;











/** Dump the mempool to disk. */
bool DumpMempool();

/** Load the mempool from disk. */
bool LoadMempool();

//! Check whether the block associated with this index entry is pruned or not.
inline bool IsBlockPruned(const CBlockIndex* pblockindex)
{
    return (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0);
}

#endif // BITCOIN_VALIDATION_H
