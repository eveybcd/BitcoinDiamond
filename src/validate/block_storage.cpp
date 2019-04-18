// Copyright (c) 2019 The BCD Core developers

#include <validate/block_storage.h>
#include <validate/cchain_state.h>
#include <validate/chain_cache.h>


std::atomic_bool fReindex(false);
std::unique_ptr<CBlockTreeDB> pblocktree;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;

FILE* BlockStorage::OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, fReadOnly ? "rb": "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

/** Open an undo file (rev?????.dat) */
FILE* BlockStorage::OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

bool BlockStorage::UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex)
{
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

FILE* BlockStorage::OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

bool BlockStorage::WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << messageStart << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool BlockStorage::ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();
    bool isBCDBlock = false;
    CBlockIndex* pindexPrev = nullptr;
    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }
    if (!block.hashPrevBlock.IsNull()){
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return error("%s: block %s  prev block not found", __func__, pos.ToString());

        pindexPrev = (*mi).second;
        if ((block.nVersion & VERSIONBITS_FORK_BCD) && pindexPrev->nHeight + 1 >= consensusParams.BCDHeight)
            isBCDBlock = true;
    }
    // Check the header
    if (!CheckProofOfWork(block.GetPoWHash(isBCDBlock), block.nBits, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}


bool BlockStorage::ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& message_start)
{
    CDiskBlockPos hpos = pos;
    hpos.nPos -= 8; // Seek back 8 bytes for meta header
    CAutoFile filein(OpenBlockFile(hpos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        return error("%s: OpenBlockFile failed for %s", __func__, pos.ToString());
    }

    try {
        CMessageHeader::MessageStartChars blk_start;
        unsigned int blk_size;

        filein >> blk_start >> blk_size;

        if (memcmp(blk_start, message_start, CMessageHeader::MESSAGE_START_SIZE)) {
            return error("%s: Block magic mismatch for %s: %s versus expected %s", __func__, pos.ToString(),
                         HexStr(blk_start, blk_start + CMessageHeader::MESSAGE_START_SIZE),
                         HexStr(message_start, message_start + CMessageHeader::MESSAGE_START_SIZE));
        }

        if (blk_size > MAX_SIZE) {
            return error("%s: Block data is larger than maximum deserialization size for %s: %s versus %s", __func__, pos.ToString(),
                         blk_size, MAX_SIZE);
        }

        block.resize(blk_size); // Zeroing of memory is intentional here
        filein.read((char*)block.data(), blk_size);
    } catch(const std::exception& e) {
        return error("%s: Read from block file failed: %s for %s", __func__, e.what(), pos.ToString());
    }

    return true;
}

bool BlockStorage::UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << messageStart << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

void BlockStorage::UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* This function is called from the RPC code for pruneblockchain */
void BlockStorage::PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::NONE, nManualPruneHeight)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 *
 * If FlushStateMode::NONE is used, then FlushStateToDisk(...) won't do anything
 * besides checking if we need to prune.
 */
bool BlockStorage::FlushStateToDisk(const CChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    std::set<int> setFilesToPrune;
    bool full_flush_completed = false;
    try {
        {
            bool fFlushForPrune = false;
            bool fDoFullFlush = false;
            LOCK(cs_LastBlockFile);
            if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
                if (nManualPruneHeight > 0) {
                    FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
                } else {
                    FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                    fCheckForPruning = false;
                }
                if (!setFilesToPrune.empty()) {
                    fFlushForPrune = true;
                    if (!fHavePruned) {
                        pblocktree->WriteFlag("prunedblockfiles", true);
                        fHavePruned = true;
                    }
                }
            }
            int64_t nNow = GetTimeMicros();
            // Avoid writing/flushing immediately after startup.
            if (nLastWrite == 0) {
                nLastWrite = nNow;
            }
            if (nLastFlush == 0) {
                nLastFlush = nNow;
            }
            int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
            int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
            int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
            // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
            bool fCacheLarge = mode == FlushStateMode::PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
            // The cache is over the limit, we have to write now.
            bool fCacheCritical = mode == FlushStateMode::IF_NEEDED && cacheSize > nTotalSpace;
            // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
            bool fPeriodicWrite = mode == FlushStateMode::PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
            // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
            bool fPeriodicFlush = mode == FlushStateMode::PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
            // Combine all conditions that result in a full cache flush.
            fDoFullFlush = (mode == FlushStateMode::ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
            // Write blocks and block index to disk.
            if (fDoFullFlush || fPeriodicWrite) {
                // Depend on nMinDiskSpace to ensure we can write block index
                if (!CheckDiskSpace(0, true))
                    return state.Error("out of disk space");
                // First make sure all block and undo data is flushed to disk.
                FlushBlockFile();
                // Then update all block file information (which may refer to block and undo files).
                {
                    std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                    vFiles.reserve(dirtyFileInfo.size());
                    for (std::set<int>::iterator it = dirtyFileInfo.begin(); it != dirtyFileInfo.end(); ) {
                        vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                        dirtyFileInfo.erase(it++);
                    }
                    std::vector<const CBlockIndex*> vBlocks;
                    vBlocks.reserve(dirtyBlockIndex.size());
                    for (std::set<CBlockIndex*>::iterator it = dirtyBlockIndex.begin(); it != dirtyBlockIndex.end(); ) {
                        vBlocks.push_back(*it);
                        dirtyBlockIndex.erase(it++);
                    }
                    if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                        return AbortNode(state, "Failed to write to block index database");
                    }
                }
                // Finally remove any pruned files
                if (fFlushForPrune)
                    UnlinkPrunedFiles(setFilesToPrune);
                nLastWrite = nNow;
            }
            // Flush best chain related state. This can only be done if the blocks / block index write was also done.
            if (fDoFullFlush && !pcoinsTip->GetBestBlock().IsNull()) {
                // Typical Coin structures on disk are around 48 bytes in size.
                // Pushing a new one to the database can cause it to be written
                // twice (once in the log, and once in the tables). This is already
                // an overestimation, as most will delete an existing entry or
                // overwrite one. Still, use a conservative safety factor of 2.
                if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
                    return state.Error("out of disk space");
                // Flush the chainstate (which may refer to block index entries).
                if (!pcoinsTip->Flush())
                    return AbortNode(state, "Failed to write to coin database");
                nLastFlush = nNow;
                full_flush_completed = true;
            }
        }
        if (full_flush_completed) {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().ChainStateFlushed(chainActive.GetLocator());
        }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void BlockStorage::FlushBlockFile(bool fFinalize)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);
    bool status = true;

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            status &= TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize);
        status &= FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            status &= TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize);
        status &= FileCommit(fileOld);
        fclose(fileOld);
    }

    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the result of an I/O error.");
    }
}

//
// CBlock and CBlockIndex
//

bool BlockStorage::ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    CDiskBlockPos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                     pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

bool BlockStorage::ReadRawBlockFromDisk(std::vector<uint8_t>& block, const CBlockIndex* pindex, const CMessageHeader::MessageStartChars& message_start)
{
    CDiskBlockPos block_pos;
    {
        LOCK(cs_main);
        block_pos = pindex->GetBlockPos();
    }

    return ReadRawBlockFromDisk(block, block_pos, message_start);
}

void BlockStorage::FlushStateToDisk() {
    CValidationState state;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::ALWAYS)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
void BlockStorage::FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
void BlockStorage::FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        // On a prune event, the chainstate DB is flushed.
        // To avoid excessive prune events negating the benefit of high dbcache
        // values, we should not prune too rapidly.
        // So when pruning in IBD, increase the buffer a bit to avoid a re-prune too soon.
        if (IsInitialBlockDownload()) {
            // Since this is only relevant during IBD, we use a fixed 10%
            nBuffer += nPruneTarget / 10;
        }

        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
             nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
             ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
             nLastBlockWeCanPrune, count);
}

/* Prune a block file (modify associated database entries)*/
void BlockStorage::PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    dirtyFileInfo.insert(fileNumber);
}

void BlockStorage::PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();
    if (!FlushStateToDisk(chainparams, state, FlushStateMode::NONE)) {
        LogPrintf("%s: failed to flush state (%s)\n", __func__, FormatStateMessage(state));
    }
}

fs::path BlockStorage::GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetBlocksDir() / strprintf("%s%05u.dat", prefix, pos.nFile);
}

bool BlockStorage::LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> buf;
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != chainparams.GetConsensus().hashGenesisBlock && !LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                                 block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                        continue;
                    }

                    // process in case the block isn't known yet
                    CBlockIndex* pindex = LookupBlockIndex(hash);
                    if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                        CValidationState state;
                        if (g_chainstate.AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr)) {
                            nLoaded++;
                        }
                        if (state.IsError()) {
                            break;
                        }
                    } else if (hash != chainparams.GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                        LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                    }
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                     head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (g_chainstate.AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t BlockStorage::CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

CBlockIndex* BlockStorage::LookupBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

bool BlockStorage::FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos, true)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return error("out of disk space");
        }
    }

    dirtyFileInfo.insert(nFile);
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
CDiskBlockPos BlockStorage::SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const CDiskBlockPos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
    CDiskBlockPos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return CDiskBlockPos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return CDiskBlockPos();
        }
    }
    return blockPos;
}

unsigned int BlockStorage::GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) {
    AssertLockHeld(cs_main);

    unsigned int flags = SCRIPT_VERIFY_NONE;

    // BIP16 didn't become active until Apr 1 2012 (on mainnet, and
    // retroactively applied to testnet)
    // However, only one historical block violated the P2SH rules (on both
    // mainnet and testnet), so for simplicity, always leave P2SH
    // on except for the one violating block.
    if (consensusparams.BIP16Exception.IsNull() || // no bip16 exception on this chain
        pindex->phashBlock == nullptr || // this is a new candidate block, eg from TestBlockValidity()
        *pindex->phashBlock != consensusparams.BIP16Exception) // this block isn't the historical exception
    {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Enforce WITNESS rules whenever P2SH is in effect (and the segwit
    // deployment is defined).
    if (flags & SCRIPT_VERIFY_P2SH && IsScriptWitnessEnabled(consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    if (VersionBitsState(pindex->pprev, consensusparams, Consensus::DEPLOYMENT_CSV, versionbitscache) == ThresholdState::ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    if (IsNullDummyEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}

bool BlockStorage::CheckDiskSpace(uint64_t nAdditionalBytes, bool blocks_dir)
{
    uint64_t nFreeBytesAvailable = fs::space(blocks_dir ? GetBlocksDir() : GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

bool BlockStorage::IsNullDummyEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == ThresholdState::ACTIVE);
}

// 0.13.0 was shipped with a segwit deployment defined for testnet, but not for
// mainnet. We no longer need to support disabling the segwit deployment
// except for testing purposes, due to limitations of the functional test
// environment. See test/functional/p2p-segwit.py.
bool BlockStorage::IsScriptWitnessEnabled(const Consensus::Params& params)
{
    return params.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0;
}


bool BlockStorage::LoadBlockIndexDB(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!g_chainstate.LoadBlockIndex(chainparams.GetConsensus(), *pblocktree))
        return false;

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    return true;
}

bool BlockStorage::FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(gBlockStorage.cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = gBlockStorage.vinfoBlockFile[nFile].nUndoSize;
    nNewSize = gBlockStorage.vinfoBlockFile[nFile].nUndoSize += nAddSize;
    gBlockStorage.setDirtyFileInfo(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            gBlockStorage.setFCheckForPruning(true);
        if (gBlockStorage.CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos, true)) {
            FILE *file = gBlockStorage.OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool BlockStorage::WriteUndoDataForBlock(const CBlockUndo& blockundo, CValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        CDiskBlockPos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");
        if (!gBlockStorage.UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        gBlockStorage.setDirtyBlockIndex(pindex);
    }

    return true;
}