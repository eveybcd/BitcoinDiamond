// Copyright (c) 2019 The BCD Core developers

#ifndef BITCOINDIAMOND_NET_MSG_HANDLE_H
#define BITCOINDIAMOND_NET_MSG_HANDLE_H

#include <network/net_cnode_state.h>
#include <network/net_blocktx.h>
#include "netmessagemaker.h"

/** SHA256("main address relay")[0:8] */
static constexpr uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL;
/** Protect at least this many outbound peers from disconnection due to slow/
 * behind headers chain.
 */
static constexpr int32_t MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT = 4;


class NetMsgHandle
{
private:
    /**
    * Filter for transactions that were recently rejected by
    * AcceptToMemoryPool. These are not rerequested until the chain tip
    * changes, at which point the entire filter is reset.
    *
    * Without this filter we'd be re-requesting txs from each of our peers,
    * increasing bandwidth consumption considerably. For instance, with 100
    * peers, half of which relay a tx we don't accept, that might be a 50x
    * bandwidth increase. A flooding attacker attempting to roll-over the
    * filter using minimum-sized, 60byte, transactions might manage to send
    * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
    * two minute window to send invs to us.
    *
    * Decreasing the false positive rate is fairly cheap, so we pick one in a
    * million to make it highly unlikely for users to have issues with this
    * filter.
    *
    * Memory used: 1.3 MB
    */
    std::unique_ptr<CRollingBloomFilter> recentRejects GUARDED_BY(cs_main);
    uint256 hashRecentRejectsChainTip GUARDED_BY(cs_main);

    /** Number of preferable block download peers. */
    int nPreferredDownload GUARDED_BY(cs_main) = 0;

    /** Number of outbound peers with m_chain_sync.m_protect. */
    int g_outbound_peers_with_protect_from_disconnect GUARDED_BY(cs_main) = 0;

    std::shared_ptr<NetBlockTx> netBlockTxPtr;
    /**
     * Sources of received blocks, saved to be able to send them reject
     * messages or ban them when processing happens afterwards.
     * Set mapBlockSource[hash].second to false if the node should not be
     * punished if the block is invalid.
     */
    std::map<uint256, std::pair<NodeId, bool>> mapBlockSource GUARDED_BY(cs_main);


public:
    NetMsgHandle(std::shared_ptr<NetBlockTx> netBlockTx);
    bool handleInv(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const std::atomic<bool>& interruptMsgProc, const CNetMsgMaker &msgMaker);
    void handleSendcmpct(CNode* pfrom, CDataStream& vRecv);
    bool handleAddr(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const std::atomic<bool>& interruptMsgProc);
    void handleVerack(CNode* pfrom, CConnman* connman, const CNetMsgMaker &msgMaker);
    bool handleVersion(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, CConnman* connman, bool enable_bip61);
    bool handleReject(CDataStream& vRecv);
    bool handleGetdata(CNode* pfrom, CDataStream& vRecv, CConnman* connman,const std::atomic<bool>& interruptMsgProc, const CChainParams& chainparams);
    bool handleGetblocks(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams);
    bool handleGetblocktxn(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams);
    bool handleGetheaders(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams, const CNetMsgMaker &msgMaker);
    bool handleTx(CNode* pfrom, CDataStream& vRecv, CConnman* connman, bool enable_bip61, const std::string& strCommand, const CNetMsgMaker &msgMaker);
    bool handleCmpctblock(CNode* pfrom, CDataStream& vRecv, CConnman* connman, CDataStream &blockTxnMsg, const CChainParams& chainparams, const CNetMsgMaker &msgMaker);
    bool handleBlocktxn(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams, const CNetMsgMaker &msgMaker);
    bool handleHeaders(CNode* pfrom, CDataStream& vRecv, CConnman* connman, const CChainParams& chainparams);
    bool handleBlock(CNode* pfrom, CDataStream& vRecv, const CChainParams& chainparams);
    bool handleGetaddr(CNode* pfrom, CConnman* connman);
    bool handleMempool(CNode* pfrom, CConnman* connman);
    bool handlePing(CNode* pfrom, CConnman* connman, CDataStream& vRecv, const CNetMsgMaker msgMaker);
    bool handlePong(CNode* pfrom, CDataStream& vRecv, int64_t nTimeReceived);
    bool handleFilterload(CNode* pfrom, CDataStream& vRecv);
    bool handleFilteradd(CNode* pfrom, CDataStream& vRecv);

    void PushNodeVersion(CNode *pnode, CConnman* connman, int64_t nTime);
    uint32_t GetFetchFlags(CNode* pfrom) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime, CNodeState *state);
    int getNPreferredDownload() {return nPreferredDownload;}
    bool IsOutboundDisconnectionCandidate(const CNode *node);
    bool AlreadyHave(const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    std::map<uint256, std::pair<NodeId, bool>>& getMapBlockSource() {return mapBlockSource;}

private:
    bool ProcessHeadersMessage(CNode *pfrom, CConnman *connman, const std::vector<CBlockHeader>& headers, const CChainParams& chainparams, bool punish_duplicate_invalid);
    void RelayAddress(const CAddress& addr, bool fReachable, CConnman* connman);
    void RelayTransaction(const CTransaction& tx, CConnman* connman);
    void SendBlockTransactions(const CBlock& block, const BlockTransactionsRequest& req, CNode* pfrom, CConnman* connman);
    void UpdatePreferredDownload(CNode* node, CNodeState* state) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
};
#endif //BITCOINDIAMOND_NET_MSG_HANDLE_H
