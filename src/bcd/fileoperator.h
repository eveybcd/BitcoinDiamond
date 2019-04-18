// Copyright (c) 2019 The BCD Core developers

#ifndef BITCOINDIAMOND_FILEOPERATOR_H
#define BITCOINDIAMOND_FILEOPERATOR_H

#include <bcd/validationcommon.h>


extern std::atomic_bool fReindex;
/** Global variable that points to the active block tree (protected by cs_main) */
extern std::unique_ptr<CBlockTreeDB> pblocktree;
extern size_t nCoinCacheUsage;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;

/** Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage();
CBlockIndex* LookupBlockIndex(const uint256& hash);
FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex);
/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);

/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);
bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& message_start);

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart);


static bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart);

bool static FlushStateToDisk(const CChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight);

void static FlushBlockFile(bool fFinalize = false);


/** Functions for disk access for blocks */
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams);
bool ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start);


/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk();


// See definition for documentation
static bool FlushStateToDisk(const CChainParams& chainParams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);


/**
 *  Mark one block file as pruned.
 */
void PruneOneBlockFile(const int fileNumber);

/**
 *  Actually unlink the specified files
 */
void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune);


/** Prune block files and flush state to disk. */
void PruneAndFlush();
/** Prune block files up to a given height */
void PruneBlockFilesManual(int nManualPruneHeight);


/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
/** Import blocks from an external file */
bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp = nullptr);



static void NotifyHeaderTip() LOCKS_EXCLUDED(cs_main);

#endif //BITCOINDIAMOND_FILEOPERATOR_H
