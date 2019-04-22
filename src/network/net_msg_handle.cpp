// Copyright (c) 2019 The BCD Core developers

#include <network/net_msg_handle.h>
#include <network/netbase.h>



NetMsgHandle::NetMsgHandle(std::shared_ptr<NetBlockTx> netBlockTx) {
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));
    netBlockTxPtr = netBlockTx;
}


bool NetMsgHandle::AlreadyHave(const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    switch (inv.type)
    {
        case MSG_TX:
        case MSG_WITNESS_TX:
        {
            assert(recentRejects);
            if (chainActive.Tip()->GetBlockHash() != hashRecentRejectsChainTip)
            {
                // If the chain tip has changed previously rejected transactions
                // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
                // or a double-spend. Reset the rejects filter and give those
                // txs a second chance.
                hashRecentRejectsChainTip = chainActive.Tip()->GetBlockHash();
                recentRejects->reset();
            }

            {
                LOCK(g_cs_orphans);
                if (mapOrphanTransactions.count(inv.hash)) return true;
            }

            return recentRejects->contains(inv.hash) ||
                   mempool.exists(inv.hash) ||
                   pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 0)) || // Best effort: only try output 0 and 1
                   pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 1));
        }
        case MSG_BLOCK:
        case MSG_WITNESS_BLOCK:
            return gBlockStorage.LookupBlockIndex(inv.hash) != nullptr;
    }
    // Don't know what it is, just say we already got one
    return true;
}

void NetMsgHandle::RelayTransaction(const CTransaction& tx, CConnman* connman)
{
    CInv inv(MSG_TX, tx.GetHash());
    connman->ForEachNode([&inv](CNode* pnode)
                         {
                             pnode->PushInventory(inv);
                         });
}

void NetMsgHandle::RelayAddress(const CAddress& addr, bool fReachable, CConnman* connman)
{
    unsigned int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)

    // Relay to a limited number of other nodes
    // Use deterministic randomness to send to the same nodes for 24 hours
    // at a time so the addrKnowns of the chosen nodes prevent repeats
    uint64_t hashAddr = addr.GetHash();
    const CSipHasher hasher = connman->GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY).Write(hashAddr << 32).Write((GetTime() + hashAddr) / (24*60*60));
    FastRandomContext insecure_rand;

    std::array<std::pair<uint64_t, CNode*>,2> best{{{0, nullptr}, {0, nullptr}}};
    assert(nRelayNodes <= best.size());

    auto sortfunc = [&best, &hasher, nRelayNodes](CNode* pnode) {
        if (pnode->nVersion >= CADDR_TIME_VERSION) {
            uint64_t hashKey = CSipHasher(hasher).Write(pnode->GetId()).Finalize();
            for (unsigned int i = 0; i < nRelayNodes; i++) {
                if (hashKey > best[i].first) {
                    std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
                    best[i] = std::make_pair(hashKey, pnode);
                    break;
                }
            }
        }
    };

    auto pushfunc = [&addr, &best, nRelayNodes, &insecure_rand] {
        for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; i++) {
            best[i].second->PushAddress(addr, insecure_rand);
        }
    };

    connman->ForEachNodeThen(std::move(sortfunc), std::move(pushfunc));
}

uint32_t NetMsgHandle::GetFetchFlags(CNode* pfrom) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
    uint32_t nFetchFlags = 0;
    if ((pfrom->GetLocalServices() & NODE_WITNESS) && State(pfrom->GetId())->fHaveWitness) {
        nFetchFlags |= MSG_WITNESS_FLAG;
    }
    return nFetchFlags;
}

void NetMsgHandle::SendBlockTransactions(const CBlock& block, const BlockTransactionsRequest& req, CNode* pfrom, CConnman* connman) {
    BlockTransactions resp(req);
    for (size_t i = 0; i < req.indexes.size(); i++) {
        if (req.indexes[i] >= block.vtx.size()) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100, strprintf("Peer %d sent us a getblocktxn with out-of-bounds tx indices", pfrom->GetId()));
            return;
        }
        resp.txn[i] = block.vtx[req.indexes[i]];
    }
    LOCK(cs_main);
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    int nSendFlags = State(pfrom->GetId())->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
    connman->PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::BLOCKTXN, resp));
}

void NetMsgHandle::FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime, CNodeState *state) {

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        fUpdateConnectionTime = true;
    }

    for (const QueuedBlock& entry : state->vBlocksInFlight) {
        mapBlocksInFlight.erase(entry.hash);
    }
    netBlockTxPtr->EraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;
    nPeersWithValidatedDownloads -= (state->nBlocksInFlightValidHeaders != 0);
    assert(nPeersWithValidatedDownloads >= 0);
    g_outbound_peers_with_protect_from_disconnect -= state->m_chain_sync.m_protect;
    assert(g_outbound_peers_with_protect_from_disconnect >= 0);

    mapNodeState.erase(nodeid);

    if (mapNodeState.empty()) {
        // Do a consistency check after the last peer is removed.
        assert(mapBlocksInFlight.empty());
        assert(nPreferredDownload == 0);
        assert(nPeersWithValidatedDownloads == 0);
        assert(g_outbound_peers_with_protect_from_disconnect == 0);
    }
    LogPrint(BCLog::NET, "Cleared nodestate for peer=%d\n", nodeid);
}

bool NetMsgHandle::ProcessHeadersMessage(CNode *pfrom, CConnman *connman, const std::vector<CBlockHeader>& headers, const CChainParams& chainparams, bool punish_duplicate_invalid)
{
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    size_t nCount = headers.size();

    if (nCount == 0) {
        // Nothing interesting. Stop asking this peers for more headers.
        return true;
    }

    bool received_new_header = false;
    const CBlockIndex *pindexLast = nullptr;
    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());

        // If this looks like it could be a block announcement (nCount <
        // MAX_BLOCKS_TO_ANNOUNCE), use special logic for handling headers that
        // don't connect:
        // - Send a getheaders message in response to try to connect the chain.
        // - The peer can send up to MAX_UNCONNECTING_HEADERS in a row that
        //   don't connect before giving DoS points
        // - Once a headers message is received that is valid and does connect,
        //   nUnconnectingHeaders gets reset back to 0.
        if (!gBlockStorage.LookupBlockIndex(headers[0].hashPrevBlock) && nCount < MAX_BLOCKS_TO_ANNOUNCE) {
            nodestate->nUnconnectingHeaders++;
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), uint256()));
            LogPrint(BCLog::NET, "received header %s: missing prev block %s, sending getheaders (%d) to end (peer=%d, nUnconnectingHeaders=%d)\n",
                     headers[0].GetHash().ToString(),
                     headers[0].hashPrevBlock.ToString(),
                     pindexBestHeader->nHeight,
                     pfrom->GetId(), nodestate->nUnconnectingHeaders);
            // Set hashLastUnknownBlock for this peer, so that if we
            // eventually get the headers - even from a different peer -
            // we can use this peer to download.
            netBlockTxPtr->UpdateBlockAvailability(pfrom->GetId(), headers.back().GetHash());

            if (nodestate->nUnconnectingHeaders % MAX_UNCONNECTING_HEADERS == 0) {
                Misbehaving(pfrom->GetId(), 20);
            }
            return true;
        }

        uint256 hashLastBlock;
        for (const CBlockHeader& header : headers) {
            if (!hashLastBlock.IsNull() && header.hashPrevBlock != hashLastBlock) {
                Misbehaving(pfrom->GetId(), 20, "non-continuous headers sequence");
                return false;
            }
            hashLastBlock = header.GetHash();
        }

        // If we don't have the last header, then they'll have given us
        // something new (if these headers are valid).
        if (!gBlockStorage.LookupBlockIndex(hashLastBlock)) {
            received_new_header = true;
        }
    }

    CValidationState state;
    CBlockHeader first_invalid_header;
    if (!ProcessNewBlockHeaders(headers, state, chainparams, &pindexLast, &first_invalid_header)) {
        int nDoS;
        if (state.IsInvalid(nDoS)) {
            LOCK(cs_main);
            if (nDoS > 0) {
                Misbehaving(pfrom->GetId(), nDoS, "invalid header received");
            } else {
                LogPrint(BCLog::NET, "peer=%d: invalid header received\n", pfrom->GetId());
            }
            if (punish_duplicate_invalid && gBlockStorage.LookupBlockIndex(first_invalid_header.GetHash())) {
                // Goal: don't allow outbound peers to use up our outbound
                // connection slots if they are on incompatible chains.
                //
                // We ask the caller to set punish_invalid appropriately based
                // on the peer and the method of header delivery (compact
                // blocks are allowed to be invalid in some circumstances,
                // under BIP 152).
                // Here, we try to detect the narrow situation that we have a
                // valid block header (ie it was valid at the time the header
                // was received, and hence stored in mapBlockIndex) but know the
                // block is invalid, and that a peer has announced that same
                // block as being on its active chain.
                // Disconnect the peer in such a situation.
                //
                // Note: if the header that is invalid was not accepted to our
                // mapBlockIndex at all, that may also be grounds for
                // disconnecting the peer, as the chain they are on is likely
                // to be incompatible. However, there is a circumstance where
                // that does not hold: if the header's timestamp is more than
                // 2 hours ahead of our current time. In that case, the header
                // may become valid in the future, and we don't want to
                // disconnect a peer merely for serving us one too-far-ahead
                // block header, to prevent an attacker from splitting the
                // network by mining a block right at the 2 hour boundary.
                //
                // TODO: update the DoS logic (or, rather, rewrite the
                // DoS-interface between validate and net_processing) so that
                // the interface is cleaner, and so that we disconnect on all the
                // reasons that a peer's headers chain is incompatible
                // with ours (eg block->nVersion softforks, MTP violations,
                // etc), and not just the duplicate-invalid case.
                pfrom->fDisconnect = true;
            }
            return false;
        }
    }

    {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());
        if (nodestate->nUnconnectingHeaders > 0) {
            LogPrint(BCLog::NET, "peer=%d: resetting nUnconnectingHeaders (%d -> 0)\n", pfrom->GetId(), nodestate->nUnconnectingHeaders);
        }
        nodestate->nUnconnectingHeaders = 0;

        assert(pindexLast);
        netBlockTxPtr->UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        // From here, pindexBestKnownBlock should be guaranteed to be non-null,
        // because it is set in UpdateBlockAvailability. Some nullptr checks
        // are still present, however, as belt-and-suspenders.

        if (received_new_header && pindexLast->nChainWork > chainActive.Tip()->nChainWork) {
            nodestate->m_last_block_announcement = GetTime();
        }

        if (nCount == MAX_HEADERS_RESULTS) {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            LogPrint(BCLog::NET, "more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->GetId(), pfrom->nStartingHeight);
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexLast), uint256()));
        }

        bool fCanDirectFetch = CanDirectFetch(chainparams.GetConsensus());
        // If this set of headers is valid and ends in a block with at least as
        // much work as our tip, download as much as possible.
        if (fCanDirectFetch && pindexLast->IsValid(BLOCK_VALID_TREE) && chainActive.Tip()->nChainWork <= pindexLast->nChainWork) {
            std::vector<const CBlockIndex*> vToFetch;
            const CBlockIndex *pindexWalk = pindexLast;
            // Calculate all the blocks we'd need to switch to pindexLast, up to a limit.
            while (pindexWalk && !chainActive.Contains(pindexWalk) && vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                if (!(pindexWalk->nStatus & BLOCK_HAVE_DATA) &&
                    !mapBlocksInFlight.count(pindexWalk->GetBlockHash()) &&
                    (!IsWitnessEnabled(pindexWalk->pprev, chainparams.GetConsensus()) || State(pfrom->GetId())->fHaveWitness)) {
                    // We don't have this block, and it's not yet in flight.
                    vToFetch.push_back(pindexWalk);
                }
                pindexWalk = pindexWalk->pprev;
            }
            // If pindexWalk still isn't on our main chain, we're looking at a
            // very large reorg at a time we think we're close to caught up to
            // the main chain -- this shouldn't really happen.  Bail out on the
            // direct fetch and rely on parallel download instead.
            if (!chainActive.Contains(pindexWalk)) {
                LogPrint(BCLog::NET, "Large reorg, won't direct fetch to %s (%d)\n",
                         pindexLast->GetBlockHash().ToString(),
                         pindexLast->nHeight);
            } else {
                std::vector<CInv> vGetData;
                // Download as much as possible, from earliest to latest.
                for (const CBlockIndex *pindex : reverse_iterate(vToFetch)) {
                    if (nodestate->nBlocksInFlight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                        // Can't download any more from this peer
                        break;
                    }
                    uint32_t nFetchFlags = GetFetchFlags(pfrom);
                    vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
                    netBlockTxPtr->MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), pindex);
                    LogPrint(BCLog::NET, "Requesting block %s from  peer=%d\n",
                             pindex->GetBlockHash().ToString(), pfrom->GetId());
                }
                if (vGetData.size() > 1) {
                    LogPrint(BCLog::NET, "Downloading blocks toward %s (%d) via headers direct fetch\n",
                             pindexLast->GetBlockHash().ToString(), pindexLast->nHeight);
                }
                if (vGetData.size() > 0) {
                    if (nodestate->fSupportsDesiredCmpctVersion && vGetData.size() == 1 && mapBlocksInFlight.size() == 1 && pindexLast->pprev->IsValid(BLOCK_VALID_CHAIN)) {
                        // In any case, we want to download using a compact block, not a regular one
                        vGetData[0] = CInv(MSG_CMPCT_BLOCK, vGetData[0].hash);
                    }
                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                }
            }
        }
        // If we're in IBD, we want outbound peers that will serve us a useful
        // chain. Disconnect peers that are on chains with insufficient work.
        if (IsInitialBlockDownload() && nCount != MAX_HEADERS_RESULTS) {
            // When nCount < MAX_HEADERS_RESULTS, we know we have no more
            // headers to fetch from this peer.
            if (nodestate->pindexBestKnownBlock && nodestate->pindexBestKnownBlock->nChainWork < nMinimumChainWork) {
                // This peer has too little work on their headers chain to help
                // us sync -- disconnect if using an outbound slot (unless
                // whitelisted or addnode).
                // Note: We compare their tip to nMinimumChainWork (rather than
                // chainActive.Tip()) because we won't start block download
                // until we have a headers chain that has at least
                // nMinimumChainWork, even if a peer has a chain past our tip,
                // as an anti-DoS measure.
                if (IsOutboundDisconnectionCandidate(pfrom)) {
                    LogPrintf("Disconnecting outbound peer %d -- headers chain has insufficient work\n", pfrom->GetId());
                    pfrom->fDisconnect = true;
                }
            }
        }

        if (!pfrom->fDisconnect && IsOutboundDisconnectionCandidate(pfrom) && nodestate->pindexBestKnownBlock != nullptr) {
            // If this is an outbound peer, check to see if we should protect
            // it from the bad/lagging chain logic.
            if (g_outbound_peers_with_protect_from_disconnect < MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT && nodestate->pindexBestKnownBlock->nChainWork >= chainActive.Tip()->nChainWork && !nodestate->m_chain_sync.m_protect) {
                LogPrint(BCLog::NET, "Protecting outbound peer=%d from eviction\n", pfrom->GetId());
                nodestate->m_chain_sync.m_protect = true;
                ++g_outbound_peers_with_protect_from_disconnect;
            }
        }
    }

    return true;
}


void NetMsgHandle::UpdatePreferredDownload(CNode* node, CNodeState* state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload = (!node->fInbound || node->fWhitelisted) && !node->fOneShot && !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

void NetMsgHandle::PushNodeVersion(CNode *pnode, CConnman* connman, int64_t nTime)
{
    ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
    uint64_t nonce = pnode->GetLocalNonce();
    int nNodeStartingHeight = pnode->GetMyStartingHeight();
    NodeId nodeid = pnode->GetId();
    CAddress addr = pnode->addr;

    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    connman->PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe,
                                                                      nonce, strSubVersion, nNodeStartingHeight, ::fRelayTxes));

    if (fLogIPs) {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), addrYou.ToString(), nodeid);
    } else {
        LogPrint(BCLog::NET, "send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), nodeid);
    }
}

bool NetMsgHandle::handleReject(CDataStream& vRecv)
{
    if (LogAcceptCategory(BCLog::NET)) {
        try {
            std::string strMsg; unsigned char ccode; std::string strReason;
            vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

            std::ostringstream ss;
            ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

            if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX)
            {
                uint256 hash;
                vRecv >> hash;
                ss << ": hash " << hash.ToString();
            }
            LogPrint(BCLog::NET, "Reject %s\n", SanitizeString(ss.str()));
        } catch (const std::ios_base::failure&) {
            // Avoid feedback loops by preventing reject messages from triggering a new reject message.
            LogPrint(BCLog::NET, "Unparseable reject message received\n");
        }
    }
    return true;

}

bool NetMsgHandle::handleVersion(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman, bool enable_bip61)
{
    // Each connection can only send one version message
    if (pfrom->nVersion != 0)
    {
        if (enable_bip61) {
            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, std::string("Duplicate version message")));
        }
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }

    int64_t nTime;
    CAddress addrMe;
    CAddress addrFrom;
    uint64_t nNonce = 1;
    uint64_t nServiceInt;
    ServiceFlags nServices;
    int nVersion;
    int nSendVersion;
    std::string strSubVer;
    std::string cleanSubVer;
    int nStartingHeight = -1;
    bool fRelay = true;

    vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
    nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
    nServices = ServiceFlags(nServiceInt);
    if (!pfrom->fInbound)
    {
        connman->SetServices(pfrom->addr, nServices);
    }
    if (!pfrom->fInbound && !pfrom->fFeeler && !pfrom->m_manual_connection && !HasAllDesirableServiceFlags(nServices))
    {
        LogPrint(BCLog::NET, "peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom->GetId(), nServices, GetDesirableServiceFlags(nServices));
        if (enable_bip61) {
            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_NONSTANDARD,
                                                                              strprintf("Expected to offer services %08x", GetDesirableServiceFlags(nServices))));
        }
        pfrom->fDisconnect = true;
        return false;
    }

    if (nVersion < MIN_PEER_PROTO_VERSION)
    {
        // disconnect from peers older than this proto version
        LogPrint(BCLog::NET, "peer=%d using obsolete version %i; disconnecting\n", pfrom->GetId(), nVersion);
        if (enable_bip61) {
            connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                                                                              strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION)));
        }
        pfrom->fDisconnect = true;
        return false;
    }

    if (nVersion == 10300)
        nVersion = 300;
    if (!vRecv.empty())
        vRecv >> addrFrom >> nNonce;
    if (!vRecv.empty()) {
        vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
        cleanSubVer = SanitizeString(strSubVer);
    }
    if (!vRecv.empty()) {
        vRecv >> nStartingHeight;
    }
    if (!vRecv.empty())
        vRecv >> fRelay;
    // Disconnect if we connected to ourself
    if (pfrom->fInbound && !connman->CheckIncomingNonce(nNonce))
    {
        LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
        pfrom->fDisconnect = true;
        return true;
    }

    if (pfrom->fInbound && addrMe.IsRoutable())
    {
        SeenLocal(addrMe);
    }

    // Be shy and don't send version until we hear
    if (pfrom->fInbound)
        PushNodeVersion(pfrom, connman, GetAdjustedTime());

    connman->PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));

    pfrom->nServices = nServices;
    pfrom->SetAddrLocal(addrMe);
    {
        LOCK(pfrom->cs_SubVer);
        pfrom->strSubVer = strSubVer;
        pfrom->cleanSubVer = cleanSubVer;
    }
    pfrom->nStartingHeight = nStartingHeight;

    // set nodes not relaying blocks and tx and not serving (parts) of the historical blockchain as "clients"
    pfrom->fClient = (!(nServices & NODE_NETWORK) && !(nServices & NODE_NETWORK_LIMITED));

    // set nodes not capable of serving the complete blockchain history as "limited nodes"
    pfrom->m_limited_node = (!(nServices & NODE_NETWORK) && (nServices & NODE_NETWORK_LIMITED));

    {
        LOCK(pfrom->cs_filter);
        pfrom->fRelayTxes = fRelay; // set to true after we get the first filter* message
    }

    // Change version
    pfrom->SetSendVersion(nSendVersion);
    pfrom->nVersion = nVersion;

    if((nServices & NODE_WITNESS))
    {
        LOCK(cs_main);
        State(pfrom->GetId())->fHaveWitness = true;
    }

    // Potentially mark this peer as a preferred download peer.
    {
        LOCK(cs_main);
        UpdatePreferredDownload(pfrom, State(pfrom->GetId()));
    }

    if (!pfrom->fInbound)
    {
        // Advertise our address
        if (fListen && !IsInitialBlockDownload())
        {
            CAddress addr = GetLocalAddress(&pfrom->addr, pfrom->GetLocalServices());
            FastRandomContext insecure_rand;
            if (addr.IsRoutable())
            {
                LogPrint(BCLog::NET, "ProcessMessages: advertising address %s\n", addr.ToString());
                pfrom->PushAddress(addr, insecure_rand);
            } else if (IsPeerAddrLocalGood(pfrom)) {
                addr.SetIP(addrMe);
                LogPrint(BCLog::NET, "ProcessMessages: advertising address %s\n", addr.ToString());
                pfrom->PushAddress(addr, insecure_rand);
            }
        }

        // Get recent addresses
        if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || connman->GetAddressCount() < 1000)
        {
            connman->PushMessage(pfrom, CNetMsgMaker(nSendVersion).Make(NetMsgType::GETADDR));
            pfrom->fGetAddr = true;
        }
        connman->MarkAddressGood(pfrom->addr);
    }

    std::string remoteAddr;
    if (fLogIPs)
        remoteAddr = ", peeraddr=" + pfrom->addr.ToString();

    LogPrint(BCLog::NET, "receive version message: %s: version %d, blocks=%d, us=%s, peer=%d%s\n",
             cleanSubVer, pfrom->nVersion,
             pfrom->nStartingHeight, addrMe.ToString(), pfrom->GetId(),
             remoteAddr);

    int64_t nTimeOffset = nTime - GetTime();
    pfrom->nTimeOffset = nTimeOffset;
    AddTimeData(pfrom->addr, nTimeOffset);

    // If the peer is old enough to have the old alert system, send it the final alert.
    if (pfrom->nVersion <= 70012) {
        CDataStream finalAlert(ParseHex("60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c2075706772616465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50"), SER_NETWORK, PROTOCOL_VERSION);
        connman->PushMessage(pfrom, CNetMsgMaker(nSendVersion).Make("alert", finalAlert));
    }

    // Feeler connections exist only to verify if address is online.
    if (pfrom->fFeeler) {
        assert(pfrom->fInbound == false);
        pfrom->fDisconnect = true;
    }
    return true;
}

void NetMsgHandle::handleVerack(CNode* pfrom, CConnman* connman, const CNetMsgMaker &msgMaker)
{
    pfrom->SetRecvVersion(std::min(pfrom->nVersion.load(), PROTOCOL_VERSION));

    if (!pfrom->fInbound) {
        // Mark this node as currently connected, so we update its timestamp later.
        LOCK(cs_main);
        State(pfrom->GetId())->fCurrentlyConnected = true;
        LogPrintf("New outbound peer connected: version: %d, blocks=%d, peer=%d%s\n",
                  pfrom->nVersion.load(), pfrom->nStartingHeight, pfrom->GetId(),
                  (fLogIPs ? strprintf(", peeraddr=%s", pfrom->addr.ToString()) : ""));
    }

    if (pfrom->nVersion >= SENDHEADERS_VERSION) {
        // Tell our peer we prefer to receive headers rather than inv's
        // We send this to non-NODE NETWORK peers as well, because even
        // non-NODE NETWORK peers can announce blocks (such as pruning
        // nodes)
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDHEADERS));
    }
    if (pfrom->nVersion >= SHORT_IDS_BLOCKS_VERSION) {
        // Tell our peer we are willing to provide version 1 or 2 cmpctblocks
        // However, we do not request new block announcements using
        // cmpctblock messages.
        // We send this to non-NODE NETWORK peers as well, because
        // they may wish to request compact blocks from us
        bool fAnnounceUsingCMPCTBLOCK = false;
        uint64_t nCMPCTBLOCKVersion = 2;
        if (pfrom->GetLocalServices() & NODE_WITNESS)
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
        nCMPCTBLOCKVersion = 1;
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
    }
    pfrom->fSuccessfullyConnected = true;
}

bool NetMsgHandle::handleAddr(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const std::atomic<bool>& interruptMsgProc)
{
    std::vector<CAddress> vAddr;
    vRecv >> vAddr;
    // Don't want addr from older versions unless seeding
    if (pfrom->nVersion < CADDR_TIME_VERSION && connman->GetAddressCount() > 1000)
    {
        return true;
    }
    if (vAddr.size() > 1000)
    {
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 20, strprintf("message addr size() = %u", vAddr.size()));
        return false;
    }

    // Store the new addresses
    std::vector<CAddress> vAddrOk;
    int64_t nNow = GetAdjustedTime();
    int64_t nSince = nNow - 10 * 60;
    for (CAddress& addr : vAddr)
    {
        if (interruptMsgProc)
        {
            return true;
        }

        // We only bother storing full nodes, though this may include
        // things which we would not make an outbound connection to, in
        // part because we may make feeler connections to them.
        if (!MayHaveUsefulAddressDB(addr.nServices) && !HasAllDesirableServiceFlags(addr.nServices))
            continue;

        if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
            addr.nTime = nNow - 5 * 24 * 60 * 60;
        pfrom->AddAddressKnown(addr);
        bool fReachable = IsReachable(addr);
        if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
        {
            // Relay to a limited number of other nodes
            RelayAddress(addr, fReachable, connman);
        }
        // Do not store addresses outside our network
        if (fReachable)
            vAddrOk.push_back(addr);
    }
    connman->AddNewAddresses(vAddrOk, pfrom->addr, 2 * 60 * 60);
    if (vAddr.size() < 1000)
        pfrom->fGetAddr = false;
    if (pfrom->fOneShot)
        pfrom->fDisconnect = true;
    return true;
}

void NetMsgHandle::handleSendcmpct(CNode* pfrom, CDataStream& vRecv)
{
    bool fAnnounceUsingCMPCTBLOCK = false;
    uint64_t nCMPCTBLOCKVersion = 0;
    vRecv >> fAnnounceUsingCMPCTBLOCK >> nCMPCTBLOCKVersion;
    if (nCMPCTBLOCKVersion == 1 || ((pfrom->GetLocalServices() & NODE_WITNESS) && nCMPCTBLOCKVersion == 2)) {
        LOCK(cs_main);
        // fProvidesHeaderAndIDs is used to "lock in" version of compact blocks we send (fWantsCmpctWitness)
        if (!State(pfrom->GetId())->fProvidesHeaderAndIDs) {
            State(pfrom->GetId())->fProvidesHeaderAndIDs = true;
            State(pfrom->GetId())->fWantsCmpctWitness = nCMPCTBLOCKVersion == 2;
        }
        if (State(pfrom->GetId())->fWantsCmpctWitness == (nCMPCTBLOCKVersion == 2)) // ignore later version announces
            State(pfrom->GetId())->fPreferHeaderAndIDs = fAnnounceUsingCMPCTBLOCK;
        if (!State(pfrom->GetId())->fSupportsDesiredCmpctVersion) {
            if (pfrom->GetLocalServices() & NODE_WITNESS)
                State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 2);
            else
                State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 1);
        }
    }
}

bool NetMsgHandle::handleInv(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const std::atomic<bool>& interruptMsgProc, const CNetMsgMaker &msgMaker)
{
    std::vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > MAX_INV_SZ)
    {
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 20, strprintf("message inv size() = %u", vInv.size()));
        return false;
    }

    bool fBlocksOnly = !fRelayTxes;

    // Allow whitelisted peers to send data other than blocks in blocks only mode if whitelistrelay is true
    if (pfrom->fWhitelisted && gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY))
        fBlocksOnly = false;

    LOCK(cs_main);

    uint32_t nFetchFlags = GetFetchFlags(pfrom);

    for (CInv &inv : vInv)
    {
        if (interruptMsgProc)
            return true;

        bool fAlreadyHave = AlreadyHave(inv);
        LogPrint(BCLog::NET, "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->GetId());

        if (inv.type == MSG_TX) {
            inv.type |= nFetchFlags;
        }

        if (inv.type == MSG_BLOCK) {
            netBlockTxPtr->UpdateBlockAvailability(pfrom->GetId(), inv.hash);
            if (!fAlreadyHave && !fImporting && !fReindex && !mapBlocksInFlight.count(inv.hash)) {
                // We used to request the full block here, but since headers-announcements are now the
                // primary method of announcement on the network, and since, in the case that a node
                // fell back to inv we probably have a reorg which we should get the headers for first,
                // we now only provide a getheaders response here. When we receive the headers, we will
                // then ask for the blocks we need.
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), inv.hash));
                LogPrint(BCLog::NET, "getheaders (%d) %s to peer=%d\n", pindexBestHeader->nHeight, inv.hash.ToString(), pfrom->GetId());
            }
        }
        else
        {
            pfrom->AddInventoryKnown(inv);
            if (fBlocksOnly) {
                LogPrint(BCLog::NET, "transaction (%s) inv sent in violation of protocol peer=%d\n", inv.hash.ToString(), pfrom->GetId());
            } else if (!fAlreadyHave && !fImporting && !fReindex && !IsInitialBlockDownload()) {
                pfrom->AskFor(inv);
            }
        }
    }
    return true;
}

bool NetMsgHandle::handleGetdata(CNode* pfrom, CDataStream& vRecv, CConnman* connman,const std::atomic<bool>& interruptMsgProc, const CChainParams& chainparams)
{
    std::vector<CInv> vInv;
    vRecv >> vInv;
    if (vInv.size() > MAX_INV_SZ)
    {
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 20, strprintf("message getdata size() = %u", vInv.size()));
        return false;
    }

    LogPrint(BCLog::NET, "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->GetId());

    if (vInv.size() > 0) {
        LogPrint(BCLog::NET, "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->GetId());
    }

    pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
    netBlockTxPtr->ProcessGetData(pfrom, chainparams, connman, interruptMsgProc);
    return true;
}

bool NetMsgHandle::handleGetblocks(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (locator.vHave.size() > MAX_LOCATOR_SZ) {
        LogPrint(BCLog::NET, "getblocks locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom->GetId());
        pfrom->fDisconnect = true;
        return true;
    }

    // We might have announced the currently-being-connected tip using a
    // compact block, which resulted in the peer sending a getblocks
    // request, which we would otherwise respond to without the new block.
    // To avoid this situation we simply verify that we are on our best
    // known chain now. This is super overkill, but we handle it better
    // for getheaders requests, and there are no known nodes which support
    // compact blocks but still use getblocks to request blocks.
    {
        std::shared_ptr<const CBlock> a_recent_block;
        {
            LOCK(cs_most_recent_block);
            a_recent_block = most_recent_block;
        }
        CValidationState state;
        if (!ActivateBestChain(state, Params(), a_recent_block)) {
            LogPrint(BCLog::NET, "failed to activate chain (%s)\n", FormatStateMessage(state));
        }
    }

    LOCK(cs_main);

    // Find the last block the caller has in the main chain
    const CBlockIndex* pindex = FindForkInGlobalIndex(chainActive, locator);

    // Send the rest of the chain
    if (pindex)
        pindex = chainActive.Next(pindex);
    int nLimit = 500;
    LogPrint(BCLog::NET, "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom->GetId());
    for (; pindex; pindex = chainActive.Next(pindex))
    {
        if (pindex->GetBlockHash() == hashStop)
        {
            LogPrint(BCLog::NET, "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            break;
        }
        // If pruning, don't inv blocks unless we have on disk and are likely to still have
        // for some reasonable time window (1 hour) that block relay might require.
        const int nPrunedBlocksLikelyToHave = MIN_BLOCKS_TO_KEEP - 3600 / chainparams.GetConsensus().nPowTargetSpacing;
        if (fPruneMode && (!(pindex->nStatus & BLOCK_HAVE_DATA) || pindex->nHeight <= chainActive.Tip()->nHeight - nPrunedBlocksLikelyToHave))
        {
            LogPrint(BCLog::NET, " getblocks stopping, pruned or too old block at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            break;
        }
        pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
        if (--nLimit <= 0)
        {
            // When this block is requested, we'll send an inv that'll
            // trigger the peer to getblocks the next batch of inventory.
            LogPrint(BCLog::NET, "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            pfrom->hashContinue = pindex->GetBlockHash();
            break;
        }
    }
    return true;
}

bool NetMsgHandle::handleGetblocktxn(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams)
{
    BlockTransactionsRequest req;
    vRecv >> req;

    std::shared_ptr<const CBlock> recent_block;
    {
        LOCK(cs_most_recent_block);
        if (most_recent_block_hash == req.blockhash)
            recent_block = most_recent_block;
        // Unlock cs_most_recent_block to avoid cs_main lock inversion
    }
    if (recent_block) {
        SendBlockTransactions(*recent_block, req, pfrom, connman);
        return true;
    }

    LOCK(cs_main);

    const CBlockIndex* pindex = gBlockStorage.LookupBlockIndex(req.blockhash);
    if (!pindex || !(pindex->nStatus & BLOCK_HAVE_DATA)) {
        LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block we don't have\n", pfrom->GetId());
        return true;
    }

    if (pindex->nHeight < chainActive.Height() - MAX_BLOCKTXN_DEPTH) {
        // If an older block is requested (should never happen in practice,
        // but can happen in tests) send a block response instead of a
        // blocktxn response. Sending a full block response instead of a
        // small blocktxn response is preferable in the case where a peer
        // might maliciously send lots of getblocktxn requests to trigger
        // expensive disk reads, because it will require the peer to
        // actually receive all the data read from disk over the network.
        LogPrint(BCLog::NET, "Peer %d sent us a getblocktxn for a block > %i deep\n", pfrom->GetId(), MAX_BLOCKTXN_DEPTH);
        CInv inv;
        inv.type = State(pfrom->GetId())->fWantsCmpctWitness ? MSG_WITNESS_BLOCK : MSG_BLOCK;
        inv.hash = req.blockhash;
        pfrom->vRecvGetData.push_back(inv);
        // The message processing loop will go around again (without pausing) and we'll respond then (without cs_main)
        return true;
    }

    CBlock block;
    bool ret = gBlockStorage.ReadBlockFromDisk(block, pindex, chainparams.GetConsensus());
    assert(ret);

    SendBlockTransactions(block, req, pfrom, connman);
    return true;
}

bool NetMsgHandle::handleGetheaders(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams, const CNetMsgMaker &msgMaker)
{
    CBlockLocator locator;
    uint256 hashStop;
    vRecv >> locator >> hashStop;

    if (locator.vHave.size() > MAX_LOCATOR_SZ) {
        LogPrint(BCLog::NET, "getheaders locator size %lld > %d, disconnect peer=%d\n", locator.vHave.size(), MAX_LOCATOR_SZ, pfrom->GetId());
        pfrom->fDisconnect = true;
        return true;
    }

    LOCK(cs_main);
    if (IsInitialBlockDownload() && !pfrom->fWhitelisted) {
        LogPrint(BCLog::NET, "Ignoring getheaders from peer=%d because node is in initial block download\n", pfrom->GetId());
        return true;
    }

    CNodeState *nodestate = State(pfrom->GetId());
    const CBlockIndex* pindex = nullptr;
    if (locator.IsNull())
    {
        // If locator is null, return the hashStop block
        pindex = gBlockStorage.LookupBlockIndex(hashStop);
        if (!pindex) {
            return true;
        }

        if (!netBlockTxPtr->BlockRequestAllowed(pindex, chainparams.GetConsensus())) {
            LogPrint(BCLog::NET, "%s: ignoring request from peer=%i for old block header that isn't in the main chain\n", __func__, pfrom->GetId());
            return true;
        }
    }
    else
    {
        // Find the last block the caller has in the main chain
        pindex = FindForkInGlobalIndex(chainActive, locator);
        if (pindex)
            pindex = chainActive.Next(pindex);
    }

    // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
    std::vector<CBlock> vHeaders;
    int nLimit = MAX_HEADERS_RESULTS;
    LogPrint(BCLog::NET, "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), pfrom->GetId());
    for (; pindex; pindex = chainActive.Next(pindex))
    {
        vHeaders.push_back(pindex->GetBlockHeader());
        if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
            break;
    }
    // pindex can be nullptr either if we sent chainActive.Tip() OR
    // if our peer has chainActive.Tip() (and thus we are sending an empty
    // headers message). In both cases it's safe to update
    // pindexBestHeaderSent to be our tip.
    //
    // It is important that we simply reset the BestHeaderSent value here,
    // and not max(BestHeaderSent, newHeaderSent). We might have announced
    // the currently-being-connected tip using a compact block, which
    // resulted in the peer sending a headers request, which we respond to
    // without the new block. By resetting the BestHeaderSent, we ensure we
    // will re-announce the new block via headers (or compact blocks again)
    // in the SendMessages logic.
    nodestate->pindexBestHeaderSent = pindex ? pindex : chainActive.Tip();
    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
    return true;
}

bool NetMsgHandle::handleTx(CNode* pfrom, CDataStream& vRecv, CConnman* connman, bool enable_bip61, const std::string& strCommand, const CNetMsgMaker &msgMaker)
{
    // Stop processing the transaction early if
    // We are in blocks only mode and peer is either not whitelisted or whitelistrelay is off
    if (!fRelayTxes && (!pfrom->fWhitelisted || !gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)))
    {
        LogPrint(BCLog::NET, "transaction sent in violation of protocol peer=%d\n", pfrom->GetId());
        return true;
    }

    std::deque<COutPoint> vWorkQueue;
    std::vector<uint256> vEraseQueue;
    CTransactionRef ptx;
    vRecv >> ptx;
    const CTransaction& tx = *ptx;

    CInv inv(MSG_TX, tx.GetHash());
    pfrom->AddInventoryKnown(inv);

    LOCK2(cs_main, g_cs_orphans);

    bool fMissingInputs = false;
    CValidationState state;

    pfrom->setAskFor.erase(inv.hash);
    mapAlreadyAskedFor.erase(inv.hash);

    std::list<CTransactionRef> lRemovedTxn;

    if (!AlreadyHave(inv) &&
        AcceptToMemoryPool(mempool, state, ptx, &fMissingInputs, &lRemovedTxn, false /* bypass_limits */, 0 /* nAbsurdFee */)) {
        mempool.check(pcoinsTip.get());
        RelayTransaction(tx, connman);
        for (unsigned int i = 0; i < tx.vout.size(); i++) {
            vWorkQueue.emplace_back(inv.hash, i);
        }

        pfrom->nLastTXTime = GetTime();

        LogPrint(BCLog::MEMPOOL, "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                 pfrom->GetId(),
                 tx.GetHash().ToString(),
                 mempool.size(), mempool.DynamicMemoryUsage() / 1000);

        // Recursively process any orphan transactions that depended on this one
        std::set<NodeId> setMisbehaving;
        while (!vWorkQueue.empty()) {
            auto itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue.front());
            vWorkQueue.pop_front();
            if (itByPrev == mapOrphanTransactionsByPrev.end())
                continue;
            for (auto mi = itByPrev->second.begin();
                 mi != itByPrev->second.end();
                 ++mi)
            {
                const CTransactionRef& porphanTx = (*mi)->second.tx;
                const CTransaction& orphanTx = *porphanTx;
                const uint256& orphanHash = orphanTx.GetHash();
                NodeId fromPeer = (*mi)->second.fromPeer;
                bool fMissingInputs2 = false;
                // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                // anyone relaying LegitTxX banned)
                CValidationState stateDummy;


                if (setMisbehaving.count(fromPeer))
                    continue;
                if (AcceptToMemoryPool(mempool, stateDummy, porphanTx, &fMissingInputs2, &lRemovedTxn, false /* bypass_limits */, 0 /* nAbsurdFee */)) {
                    LogPrint(BCLog::MEMPOOL, "   accepted orphan tx %s\n", orphanHash.ToString());
                    RelayTransaction(orphanTx, connman);
                    for (unsigned int i = 0; i < orphanTx.vout.size(); i++) {
                        vWorkQueue.emplace_back(orphanHash, i);
                    }
                    vEraseQueue.push_back(orphanHash);
                }
                else if (!fMissingInputs2)
                {
                    int nDos = 0;
                    if (stateDummy.IsInvalid(nDos) && nDos > 0)
                    {
                        // Punish peer that gave us an invalid orphan tx
                        Misbehaving(fromPeer, nDos);
                        setMisbehaving.insert(fromPeer);
                        LogPrint(BCLog::MEMPOOL, "   invalid orphan tx %s\n", orphanHash.ToString());
                    }
                    // Has inputs but not accepted to mempool
                    // Probably non-standard or insufficient fee
                    LogPrint(BCLog::MEMPOOL, "   removed orphan tx %s\n", orphanHash.ToString());
                    vEraseQueue.push_back(orphanHash);
                    if (!orphanTx.HasWitness() && !stateDummy.CorruptionPossible()) {
                        // Do not use rejection cache for witness transactions or
                        // witness-stripped transactions, as they can have been malleated.
                        // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
                        assert(recentRejects);
                        recentRejects->insert(orphanHash);
                    }
                }
                mempool.check(pcoinsTip.get());
            }
        }

        for (uint256 hash : vEraseQueue)
            netBlockTxPtr->EraseOrphanTx(hash);
    }
    else if (fMissingInputs)
    {
        bool fRejectedParents = false; // It may be the case that the orphans parents have all been rejected
        for (const CTxIn& txin : tx.vin) {
            if (recentRejects->contains(txin.prevout.hash)) {
                fRejectedParents = true;
                break;
            }
        }
        if (!fRejectedParents) {
            uint32_t nFetchFlags = GetFetchFlags(pfrom);
            for (const CTxIn& txin : tx.vin) {
                CInv _inv(MSG_TX | nFetchFlags, txin.prevout.hash);
                pfrom->AddInventoryKnown(_inv);
                if (!AlreadyHave(_inv)) pfrom->AskFor(_inv);
            }
            netBlockTxPtr->AddOrphanTx(ptx, pfrom->GetId());

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, gArgs.GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
            unsigned int nEvicted = netBlockTxPtr->LimitOrphanTxSize(nMaxOrphanTx);
            if (nEvicted > 0) {
                LogPrint(BCLog::MEMPOOL, "mapOrphan overflow, removed %u tx\n", nEvicted);
            }
        } else {
            LogPrint(BCLog::MEMPOOL, "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
            // We will continue to reject this tx since it has rejected
            // parents so avoid re-requesting it from other peers.
            recentRejects->insert(tx.GetHash());
        }
    } else {
        if (!tx.HasWitness() && !state.CorruptionPossible()) {
            // Do not use rejection cache for witness transactions or
            // witness-stripped transactions, as they can have been malleated.
            // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
            assert(recentRejects);
            recentRejects->insert(tx.GetHash());
            if (RecursiveDynamicUsage(*ptx) < 100000) {
                netBlockTxPtr->AddToCompactExtraTransactions(ptx);
            }
        } else if (tx.HasWitness() && RecursiveDynamicUsage(*ptx) < 100000) {
            netBlockTxPtr->AddToCompactExtraTransactions(ptx);
        }

        if (pfrom->fWhitelisted && gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
            // Always relay transactions received from whitelisted peers, even
            // if they were already in the mempool or rejected from it due
            // to policy, allowing the node to function as a gateway for
            // nodes hidden behind it.
            //
            // Never relay transactions that we would assign a non-zero DoS
            // score for, as we expect peers to do the same with us in that
            // case.
            int nDoS = 0;
            if (!state.IsInvalid(nDoS) || nDoS == 0) {
                LogPrintf("Force relaying tx %s from whitelisted peer=%d\n", tx.GetHash().ToString(), pfrom->GetId());
                RelayTransaction(tx, connman);
            } else {
                LogPrintf("Not relaying invalid transaction %s from whitelisted peer=%d (%s)\n", tx.GetHash().ToString(), pfrom->GetId(), FormatStateMessage(state));
            }
        }
    }

    for (const CTransactionRef& removedTx : lRemovedTxn)
        netBlockTxPtr->AddToCompactExtraTransactions(removedTx);

    int nDoS = 0;
    if (state.IsInvalid(nDoS))
    {
        LogPrint(BCLog::MEMPOOLREJ, "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
                 pfrom->GetId(),
                 FormatStateMessage(state));
        if (enable_bip61 && state.GetRejectCode() > 0 && state.GetRejectCode() < REJECT_INTERNAL) { // Never send AcceptToMemoryPool's internal codes over P2P
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                                                      state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash));
        }
        if (nDoS > 0) {
            Misbehaving(pfrom->GetId(), nDoS);
        }
    }
    return true;
}

bool NetMsgHandle::handleCmpctblock(CNode* pfrom, CDataStream& vRecv, CConnman* connman, CDataStream &blockTxnMsg, const CChainParams& chainparams, const CNetMsgMaker &msgMaker)
{
    CBlockHeaderAndShortTxIDs cmpctblock;
    vRecv >> cmpctblock;

    bool received_new_header = false;

    {
        LOCK(cs_main);

        if (!gBlockStorage.LookupBlockIndex(cmpctblock.header.hashPrevBlock)) {
            // Doesn't connect (or is genesis), instead of DoSing in AcceptBlockHeader, request deeper headers
            if (!IsInitialBlockDownload())
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), uint256()));
            return true;
        }

        if (!gBlockStorage.LookupBlockIndex(cmpctblock.header.GetHash())) {
            received_new_header = true;
        }
    }

    const CBlockIndex *pindex = nullptr;
    CValidationState state;
    if (!ProcessNewBlockHeaders({cmpctblock.header}, state, chainparams, &pindex)) {
        int nDoS;
        if (state.IsInvalid(nDoS)) {
            if (nDoS > 0) {
                LOCK(cs_main);
                Misbehaving(pfrom->GetId(), nDoS, strprintf("Peer %d sent us invalid header via cmpctblock\n", pfrom->GetId()));
            } else {
                LogPrint(BCLog::NET, "Peer %d sent us invalid header via cmpctblock\n", pfrom->GetId());
            }
            return true;
        }
    }

    // When we succeed in decoding a block's txids from a cmpctblock
    // message we typically jump to the BLOCKTXN handling code, with a
    // dummy (empty) BLOCKTXN message, to re-use the logic there in
    // completing processing of the putative block (without cs_main).
    bool fProcessBLOCKTXN = false;

    // If we end up treating this as a plain headers message, call that as well
    // without cs_main.
    bool fRevertToHeaderProcessing = false;

    // Keep a CBlock for "optimistic" compactblock reconstructions (see
    // below)
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    bool fBlockReconstructed = false;

    {
        LOCK2(cs_main, g_cs_orphans);
        // If AcceptBlockHeader returned true, it set pindex
        assert(pindex);
        netBlockTxPtr->UpdateBlockAvailability(pfrom->GetId(), pindex->GetBlockHash());

        CNodeState *nodestate = State(pfrom->GetId());

        // If this was a new header with more work than our tip, update the
        // peer's last block announcement time
        if (received_new_header && pindex->nChainWork > chainActive.Tip()->nChainWork) {
            nodestate->m_last_block_announcement = GetTime();
        }

        std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator blockInFlightIt = mapBlocksInFlight.find(pindex->GetBlockHash());
        bool fAlreadyInFlight = blockInFlightIt != mapBlocksInFlight.end();

        if (pindex->nStatus & BLOCK_HAVE_DATA) // Nothing to do here
            return true;

        if (pindex->nChainWork <= chainActive.Tip()->nChainWork || // We know something better
            pindex->nTx != 0) { // We had this block at some point, but pruned it
            if (fAlreadyInFlight) {
                // We requested this block for some reason, but our mempool will probably be useless
                // so we just grab the block via normal getdata
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom), cmpctblock.header.GetHash());
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
            }
            return true;
        }

        // If we're not close to tip yet, give up and let parallel block fetch work its magic
        if (!fAlreadyInFlight && !CanDirectFetch(chainparams.GetConsensus()))
            return true;

        if (IsWitnessEnabled(pindex->pprev, chainparams.GetConsensus()) && !nodestate->fSupportsDesiredCmpctVersion) {
            // Don't bother trying to process compact blocks from v1 peers
            // after segwit activates.
            return true;
        }

        // We want to be a bit conservative just to be extra careful about DoS
        // possibilities in compact block processing...
        if (pindex->nHeight <= chainActive.Height() + 2) {
            if ((!fAlreadyInFlight && nodestate->nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) ||
                (fAlreadyInFlight && blockInFlightIt->second.first == pfrom->GetId())) {
                std::list<QueuedBlock>::iterator* queuedBlockIt = nullptr;
                if (!netBlockTxPtr->MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), pindex, &queuedBlockIt)) {
                    if (!(*queuedBlockIt)->partialBlock)
                        (*queuedBlockIt)->partialBlock.reset(new PartiallyDownloadedBlock(&mempool));
                    else {
                        // The block was already in flight using compact blocks from the same peer
                        LogPrint(BCLog::NET, "Peer sent us compact block we were already syncing!\n");
                        return true;
                    }
                }

                PartiallyDownloadedBlock& partialBlock = *(*queuedBlockIt)->partialBlock;
                ReadStatus status = partialBlock.InitData(cmpctblock, vExtraTxnForCompact);
                if (status == READ_STATUS_INVALID) {
                    netBlockTxPtr->MarkBlockAsReceived(pindex->GetBlockHash()); // Reset in-flight state in case of whitelist
                    Misbehaving(pfrom->GetId(), 100, strprintf("Peer %d sent us invalid compact block\n", pfrom->GetId()));
                    return true;
                } else if (status == READ_STATUS_FAILED) {
                    // Duplicate txindexes, the block is now in-flight, so just request it
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom), cmpctblock.header.GetHash());
                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                    return true;
                }

                BlockTransactionsRequest req;
                for (size_t i = 0; i < cmpctblock.BlockTxCount(); i++) {
                    if (!partialBlock.IsTxAvailable(i))
                        req.indexes.push_back(i);
                }
                if (req.indexes.empty()) {
                    // Dirty hack to jump to BLOCKTXN code (TODO: move message handling into their own functions)
                    BlockTransactions txn;
                    txn.blockhash = cmpctblock.header.GetHash();
                    blockTxnMsg << txn;
                    fProcessBLOCKTXN = true;
                } else {
                    req.blockhash = pindex->GetBlockHash();
                    connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETBLOCKTXN, req));
                }
            } else {
                // This block is either already in flight from a different
                // peer, or this peer has too many blocks outstanding to
                // download from.
                // Optimistically try to reconstruct anyway since we might be
                // able to without any round trips.
                PartiallyDownloadedBlock tempBlock(&mempool);
                ReadStatus status = tempBlock.InitData(cmpctblock, vExtraTxnForCompact);
                if (status != READ_STATUS_OK) {
                    // TODO: don't ignore failures
                    return true;
                }
                std::vector<CTransactionRef> dummy;
                status = tempBlock.FillBlock(*pblock, dummy);
                if (status == READ_STATUS_OK) {
                    fBlockReconstructed = true;
                }
            }
        } else {
            if (fAlreadyInFlight) {
                // We requested this block, but its far into the future, so our
                // mempool will probably be useless - request the block normally
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom), cmpctblock.header.GetHash());
                connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                return true;
            } else {
                // If this was an announce-cmpctblock, we want the same treatment as a header message
                fRevertToHeaderProcessing = true;
            }
        }
    } // cs_main

    if (fProcessBLOCKTXN)
        return false;

    if (fRevertToHeaderProcessing) {
        // Headers received from HB compact block peers are permitted to be
        // relayed before full validate (see BIP 152), so we don't want to disconnect
        // the peer if the header turns out to be for an invalid block.
        // Note that if a peer tries to build on an invalid chain, that
        // will be detected and the peer will be banned.
        return ProcessHeadersMessage(pfrom, connman, {cmpctblock.header}, chainparams, /*punish_duplicate_invalid=*/false);
    }

    if (fBlockReconstructed) {
        // If we got here, we were able to optimistically reconstruct a
        // block that is in flight from some other peer.
        {
            LOCK(cs_main);
            mapBlockSource.emplace(pblock->GetHash(), std::make_pair(pfrom->GetId(), false));
        }
        bool fNewBlock = false;
        // Setting fForceProcessing to true means that we bypass some of
        // our anti-DoS protections in AcceptBlock, which filters
        // unrequested blocks that might be trying to waste our resources
        // (eg disk space). Because we only try to reconstruct blocks when
        // we're close to caught up (via the CanDirectFetch() requirement
        // above, combined with the behavior of not requesting blocks until
        // we have a chain with at least nMinimumChainWork), and we ignore
        // compact blocks with less work than our tip, it is safe to treat
        // reconstructed compact blocks as having been requested.
        ProcessNewBlock(chainparams, pblock, /*fForceProcessing=*/true, &fNewBlock);
        if (fNewBlock) {
            pfrom->nLastBlockTime = GetTime();
        } else {
            LOCK(cs_main);
            mapBlockSource.erase(pblock->GetHash());
        }
        LOCK(cs_main); // hold cs_main for CBlockIndex::IsValid()
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) {
            // Clear download state for this block, which is in
            // process from some other peer.  We do this after calling
            // ProcessNewBlock so that a malleated cmpctblock announcement
            // can't be used to interfere with block relay.
            netBlockTxPtr->MarkBlockAsReceived(pblock->GetHash());
        }
    }
    return true;
}

bool NetMsgHandle::handleBlocktxn(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams, const CNetMsgMaker &msgMaker)
{
    BlockTransactions resp;
    vRecv >> resp;

    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    bool fBlockRead = false;
    {
        LOCK(cs_main);

        std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator it = mapBlocksInFlight.find(resp.blockhash);
        if (it == mapBlocksInFlight.end() || !it->second.second->partialBlock ||
            it->second.first != pfrom->GetId()) {
            LogPrint(BCLog::NET, "Peer %d sent us block transactions for block we weren't expecting\n", pfrom->GetId());
            return true;
        }

        PartiallyDownloadedBlock& partialBlock = *it->second.second->partialBlock;
        ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
        if (status == READ_STATUS_INVALID) {
            netBlockTxPtr->MarkBlockAsReceived(resp.blockhash); // Reset in-flight state in case of whitelist
            Misbehaving(pfrom->GetId(), 100, strprintf("Peer %d sent us invalid compact block/non-matching block transactions\n", pfrom->GetId()));
            return true;
        } else if (status == READ_STATUS_FAILED) {
            // Might have collided, fall back to getdata now :(
            std::vector<CInv> invs;
            invs.push_back(CInv(MSG_BLOCK | GetFetchFlags(pfrom), resp.blockhash));
            connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, invs));
        } else {
            // Block is either okay, or possibly we received
            // READ_STATUS_CHECKBLOCK_FAILED.
            // Note that CheckBlock can only fail for one of a few reasons:
            // 1. bad-proof-of-work (impossible here, because we've already
            //    accepted the header)
            // 2. merkleroot doesn't match the transactions given (already
            //    caught in FillBlock with READ_STATUS_FAILED, so
            //    impossible here)
            // 3. the block is otherwise invalid (eg invalid coinbase,
            //    block is too big, too many legacy sigops, etc).
            // So if CheckBlock failed, #3 is the only possibility.
            // Under BIP 152, we don't DoS-ban unless proof of work is
            // invalid (we don't require all the stateless checks to have
            // been run).  This is handled below, so just treat this as
            // though the block was successfully read, and rely on the
            // handling in ProcessNewBlock to ensure the block index is
            // updated, reject messages go out, etc.
            netBlockTxPtr->MarkBlockAsReceived(resp.blockhash); // it is now an empty pointer
            fBlockRead = true;
            // mapBlockSource is only used for sending reject messages and DoS scores,
            // so the race between here and cs_main in ProcessNewBlock is fine.
            // BIP 152 permits peers to relay compact blocks after validating
            // the header only; we should not punish peers if the block turns
            // out to be invalid.
            mapBlockSource.emplace(resp.blockhash, std::make_pair(pfrom->GetId(), false));
        }
    } // Don't hold cs_main when we call into ProcessNewBlock
    if (fBlockRead) {
        bool fNewBlock = false;
        // Since we requested this block (it was in mapBlocksInFlight), force it to be processed,
        // even if it would not be a candidate for new tip (missing previous block, chain not long enough, etc)
        // This bypasses some anti-DoS logic in AcceptBlock (eg to prevent
        // disk-space attacks), but this should be safe due to the
        // protections in the compact block handler -- see related comment
        // in compact block optimistic reconstruction handling.
        ProcessNewBlock(chainparams, pblock, /*fForceProcessing=*/true, &fNewBlock);
        if (fNewBlock) {
            pfrom->nLastBlockTime = GetTime();
        } else {
            LOCK(cs_main);
            mapBlockSource.erase(pblock->GetHash());
        }
    }
    return true;
}

bool NetMsgHandle::handleHeaders(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams)
{
    std::vector<CBlockHeader> headers;

    // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
    unsigned int nCount = ReadCompactSize(vRecv);
    if (nCount > MAX_HEADERS_RESULTS) {
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 20, strprintf("headers message size = %u", nCount));
        return false;
    }
    headers.resize(nCount);
    for (unsigned int n = 0; n < nCount; n++) {
        vRecv >> headers[n];
        ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
    }

    // Headers received via a HEADERS message should be valid, and reflect
    // the chain the peer is on. If we receive a known-invalid header,
    // disconnect the peer if it is using one of our outbound connection
    // slots.
    bool should_punish = !pfrom->fInbound && !pfrom->m_manual_connection;
    return ProcessHeadersMessage(pfrom, connman, headers, chainparams, should_punish);
}

bool NetMsgHandle::handleBlock(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams)
{
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    vRecv >> *pblock;

    LogPrint(BCLog::NET, "received block %s peer=%d\n", pblock->GetHash().ToString(), pfrom->GetId());

    bool forceProcessing = false;
    const uint256 hash(pblock->GetHash());
    {
        LOCK(cs_main);
        // Also always process if we requested the block explicitly, as we may
        // need it even though it is not a candidate for a new best tip.
        forceProcessing |= netBlockTxPtr->MarkBlockAsReceived(hash);
        // mapBlockSource is only used for sending reject messages and DoS scores,
        // so the race between here and cs_main in ProcessNewBlock is fine.
        mapBlockSource.emplace(hash, std::make_pair(pfrom->GetId(), true));
    }
    bool fNewBlock = false;
    ProcessNewBlock(chainparams, pblock, forceProcessing, &fNewBlock);
    if (fNewBlock) {
        pfrom->nLastBlockTime = GetTime();
    } else {
        LOCK(cs_main);
        mapBlockSource.erase(pblock->GetHash());
    }
}

bool NetMsgHandle::handleGetaddr(CNode* pfrom, CConnman* connman)
{
    // This asymmetric behavior for inbound and outbound connections was introduced
    // to prevent a fingerprinting attack: an attacker can send specific fake addresses
    // to users' AddrMan and later request them by sending getaddr messages.
    // Making nodes which are behind NAT and can only make outgoing connections ignore
    // the getaddr message mitigates the attack.
    if (!pfrom->fInbound) {
        LogPrint(BCLog::NET, "Ignoring \"getaddr\" from outbound connection. peer=%d\n", pfrom->GetId());
        return true;
    }

    // Only send one GetAddr response per connection to reduce resource waste
    //  and discourage addr stamping of INV announcements.
    if (pfrom->fSentAddr) {
        LogPrint(BCLog::NET, "Ignoring repeated \"getaddr\". peer=%d\n", pfrom->GetId());
        return true;
    }
    pfrom->fSentAddr = true;

    pfrom->vAddrToSend.clear();
    std::vector<CAddress> vAddr = connman->GetAddresses();
    FastRandomContext insecure_rand;
    for (const CAddress &addr : vAddr)
        pfrom->PushAddress(addr, insecure_rand);
    return true;
}

bool NetMsgHandle::handleMempool(CNode* pfrom, CConnman* connman)
{
    if (!(pfrom->GetLocalServices() & NODE_BLOOM) && !pfrom->fWhitelisted)
    {
        LogPrint(BCLog::NET, "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom->GetId());
        pfrom->fDisconnect = true;
        return true;
    }

    if (connman->OutboundTargetReached(false) && !pfrom->fWhitelisted)
    {
        LogPrint(BCLog::NET, "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom->GetId());
        pfrom->fDisconnect = true;
        return true;
    }

    LOCK(pfrom->cs_inventory);
    pfrom->fSendMempool = true;
}
bool NetMsgHandle::handlePing(CNode* pfrom, CConnman* connman, CDataStream& vRecv, const CNetMsgMaker msgMaker)
{
    if (pfrom->nVersion > BIP0031_VERSION)
    {
        uint64_t nonce = 0;
        vRecv >> nonce;
        // Echo the message back with the nonce. This allows for two useful features:
        //
        // 1) A remote node can quickly check if the connection is operational
        // 2) Remote nodes can measure the latency of the network thread. If this node
        //    is overloaded it won't respond to pings quickly and the remote node can
        //    avoid sending us more work, like chain download requests.
        //
        // The nonce stops the remote getting confused between different pings: without
        // it, if the remote node sends a ping once per second and this node takes 5
        // seconds to respond to each, the 5th ping the remote sends would appear to
        // return very quickly.
        connman->PushMessage(pfrom, msgMaker.Make(NetMsgType::PONG, nonce));
    }
}

bool NetMsgHandle::handlePong(CNode* pfrom, CDataStream& vRecv, int64_t nTimeReceived)
{
    int64_t pingUsecEnd = nTimeReceived;
    uint64_t nonce = 0;
    size_t nAvail = vRecv.in_avail();
    bool bPingFinished = false;
    std::string sProblem;

    if (nAvail >= sizeof(nonce)) {
        vRecv >> nonce;

        // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
        if (pfrom->nPingNonceSent != 0) {
            if (nonce == pfrom->nPingNonceSent) {
                // Matching pong received, this ping is no longer outstanding
                bPingFinished = true;
                int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                if (pingUsecTime > 0) {
                    // Successful ping time measurement, replace previous
                    pfrom->nPingUsecTime = pingUsecTime;
                    pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime.load(), pingUsecTime);
                } else {
                    // This should never happen
                    sProblem = "Timing mishap";
                }
            } else {
                // Nonce mismatches are normal when pings are overlapping
                sProblem = "Nonce mismatch";
                if (nonce == 0) {
                    // This is most likely a bug in another implementation somewhere; cancel this ping
                    bPingFinished = true;
                    sProblem = "Nonce zero";
                }
            }
        } else {
            sProblem = "Unsolicited pong without ping";
        }
    } else {
        // This is most likely a bug in another implementation somewhere; cancel this ping
        bPingFinished = true;
        sProblem = "Short payload";
    }

    if (!(sProblem.empty())) {
        LogPrint(BCLog::NET, "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                 pfrom->GetId(),
                 sProblem,
                 pfrom->nPingNonceSent,
                 nonce,
                 nAvail);
    }
    if (bPingFinished) {
        pfrom->nPingNonceSent = 0;
    }
}

bool NetMsgHandle::handleFilterload(CNode* pfrom, CDataStream& vRecv)
{
    CBloomFilter filter;
    vRecv >> filter;

    if (!filter.IsWithinSizeConstraints()) {
// There is no excuse for sending a too-large filter
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 100);
    } else {
        LOCK(pfrom->cs_filter);
        pfrom->pfilter.reset(new CBloomFilter(filter));
        pfrom->pfilter->UpdateEmptyFull();
        pfrom->fRelayTxes = true;
    }
}

bool NetMsgHandle::handleFilteradd(CNode* pfrom, CDataStream& vRecv)
{
    std::vector<unsigned char> vData;
    vRecv >> vData;

// Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
// and thus, the maximum size any matched object can have) in a filteradd message
    bool bad = false;
    if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
        bad = true;
    } else {
        LOCK(pfrom->cs_filter);
        if (pfrom->pfilter) {
            pfrom->pfilter->insert(vData);
        } else {
            bad = true;
        }
    }
    if (bad) {
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 100);
    }
}

// Returns true for outbound peers, excluding manual connections, feelers, and
// one-shots
bool NetMsgHandle::IsOutboundDisconnectionCandidate(const CNode *node)
{
    return !(node->fInbound || node->m_manual_connection || node->fFeeler || node->fOneShot);
}