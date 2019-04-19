// Copyright (c) 2019 The BCD Core developers


#ifndef BITCOINDIAMOND_CHAINCACHE_H
#define BITCOINDIAMOND_CHAINCACHE_H

#include <validate/validation_common.h>
#include <validate/block_storage.h>
#include <versionbits.h>
#include <validate/validate_block.h>


/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern std::unique_ptr<CCoinsViewCache> pcoinsTip;
extern CTxMemPool mempool;
extern bool fCheckBlockIndex;
extern CCriticalSection cs_main;
extern VersionBitsCache versionbitscache;
extern CBlockPolicyEstimator feeEstimator;

extern bool fRequireStandard;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;



/** A fee rate smaller than this is considered zero fee (for relaying, mining and transaction creation) */
extern CFeeRate minRelayTxFee;









/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);
/** (try to) add transaction to memory pool
 * plTxnReplaced will be appended to with all transactions replaced from mempool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee, bool test_accept=false);

/** Transaction validation functions */

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransaction &tx, int flags = -1);
/**
 * Check if transaction will be BIP 68 final in the next block to be created.
 *
 * Simulates calling SequenceLocks() with data from the tip of the current active chain.
 * Optionally stores in LockPoints the resulting height and time calculated and the hash
 * of the block needed for calculation or skips the calculation and uses the LockPoints
 * passed in for evaluation.
 * The LockPoints should not be considered valid if CheckSequenceLocks returns false.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp = nullptr, bool useExistingLockPoints = false);









void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool);


void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age);

bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                                       bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                                       bool bypass_limits, const CAmount nAbsurdFee, bool test_accept);




#endif //BITCOINDIAMOND_CHAINCACHE_H
