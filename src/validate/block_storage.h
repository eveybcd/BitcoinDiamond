// Copyright (c) 2019 The BCD Core developers

#ifndef BITCOINDIAMOND_FILEOPERATOR_H
#define BITCOINDIAMOND_FILEOPERATOR_H

#include <validate/validation_common.h>


extern std::atomic_bool fReindex;
/** Global variable that points to the active block tree (protected by cs_main) */
extern std::unique_ptr<CBlockTreeDB> pblocktree;
extern size_t nCoinCacheUsage;
/** Number of MiB of block files that we're trying to stay below. */
extern uint64_t nPruneTarget;


class BlockStorage {

private:
/** Global flag to indicate we should check to see if there are
 *  block/undo files that should be deleted.  Set on startup
 *  or if we allocate more file space when we're in prune mode
 */
    bool fCheckForPruning = false;
    int nLastBlockFile = 0;
/** Dirty block index entries. */
    std::set<CBlockIndex *> dirtyBlockIndex;
    /** Dirty block file entries. */
    std::set<int> dirtyFileInfo;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    CCriticalSection cs_LastBlockFile;

public:
    //bool getFCheckForPruning() { return fCheckForPruning;}
    void setFCheckForPruning(bool fCheckForPruningTmp) { fCheckForPruning = fCheckForPruningTmp;}
    void setDirtyBlockIndex(CBlockIndex * cBlockIndex) {dirtyBlockIndex.insert(cBlockIndex);}
    void clearDirtyBlockIndex() {dirtyBlockIndex.clear();}
    void setLastBlockFile(int lastBlockFile) {nLastBlockFile = lastBlockFile;}
    void clearDirtyFileInfo() {dirtyFileInfo.clear();}
    void setDirtyFileInfo(int dirtyFileInfoTmp) {dirtyFileInfo.insert(dirtyFileInfoTmp);}
    void clearVinfoBlockFile() {vinfoBlockFile.clear();}

//externale interface
public:

/** Calculate the amount of disk space the block & undo files currently use */
    uint64_t CalculateCurrentUsage();

    CBlockIndex *LookupBlockIndex(const uint256 &hash);

/** Open a block file (blk?????.dat) */
    FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);

/** Functions for disk access for blocks */
    bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &consensusParams);

    bool ReadRawBlockFromDisk(std::vector<uint8_t> &block, const CBlockIndex *pindex,
                              const CMessageHeader::MessageStartChars &message_start);

/** Flush all state, indexes and buffers to disk. */
    void FlushStateToDisk();

/** Prune block files and flush state to disk. */
    void PruneAndFlush();

/** Translation to a filesystem path */
    fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);

/** Import blocks from an external file */
    bool LoadExternalBlockFile(const CChainParams &chainparams, FILE *fileIn, CDiskBlockPos *dbp = nullptr);

/** Check whether enough disk space is available for an incoming block */
    bool CheckDiskSpace(uint64_t nAdditionalBytes = 0, bool blocks_dir = false);


public:
    FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

    bool UndoWriteToDisk(const CBlockUndo &blockundo, CDiskBlockPos &pos, const uint256 &hashBlock,
                         const CMessageHeader::MessageStartChars &messageStart);

    bool WriteBlockToDisk(const CBlock &block, CDiskBlockPos &pos, const CMessageHeader::MessageStartChars &messageStart);

    bool UndoReadFromDisk(CBlockUndo &blockundo, const CBlockIndex *pindex);

    bool FlushStateToDisk(const CChainParams &chainParams, CValidationState &state, FlushStateMode mode,
                          int nManualPruneHeight = 0);

    void FlushBlockFile(bool fFinalize = false);

/** Prune block files up to a given height */
    void PruneBlockFilesManual(int nManualPruneHeight);

    CDiskBlockPos SaveBlockToDisk(const CBlock &block, int nHeight, const CChainParams &chainparams, const CDiskBlockPos *dbp);

// Returns the script flags which should be checked for a given block
    unsigned int GetBlockScriptFlags(const CBlockIndex *pindex, const Consensus::Params &chainparams);

/** Check whether NULLDUMMY (BIP 147) has activated. */
    bool IsNullDummyEnabled(const CBlockIndex *pindexPrev, const Consensus::Params &params);

    bool LoadBlockIndexDB(const CChainParams &chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    bool WriteUndoDataForBlock(const CBlockUndo& blockundo, CValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams);

private:
    FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly);
    bool IsScriptWitnessEnabled(const Consensus::Params &params);
    bool FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false);
    /**
     *  Actually unlink the specified files
     */
    void UnlinkPrunedFiles(const std::set<int> &setFilesToPrune);
    /**
     *  Mark one block file as pruned.
     */
    void PruneOneBlockFile(const int fileNumber);
    /** Functions for disk access for blocks */
    bool ReadBlockFromDisk(CBlock &block, const CDiskBlockPos &pos, const Consensus::Params &consensusParams);

    bool ReadRawBlockFromDisk(std::vector<uint8_t> &block, const CDiskBlockPos &pos,
                              const CMessageHeader::MessageStartChars &message_start);

    void FindFilesToPruneManual(std::set<int> &setFilesToPrune, int nManualPruneHeight);

    void FindFilesToPrune(std::set<int> &setFilesToPrune, uint64_t nPruneAfterHeight);

    bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

} gBlockStorage;


#endif //BITCOINDIAMOND_FILEOPERATOR_H
