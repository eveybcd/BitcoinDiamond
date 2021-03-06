// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_PROCESSING_H
#define BITCOIN_NET_PROCESSING_H

#include <network/net_cnode_state.h>
#include <network/net_blocktx.h>
#include "netmessagemaker.h"
#include <network/net_msg_handle.h>

/** Default for BIP61 (sending reject messages) */
static constexpr bool DEFAULT_ENABLE_BIP61 = true;

class PeerLogicValidation final : public CValidationInterface, public NetEventsInterface {
private:
    CConnman* const connman;
    std::shared_ptr<NetBlockTx> netBlockTxPtr;
    std::unique_ptr<NetMsgHandle> netMsghandlePtr;
    int64_t m_stale_tip_check_time; //! Next time to check for stale tip
    /** Enable BIP61 (sending reject messages) */
    const bool m_enable_bip61;
    /** Number of nodes with fSyncStarted. */
    int nSyncStarted GUARDED_BY(cs_main) = 0;

    /** Expiration-time ordered list of (expire time, relay map entry) pairs. */
    std::deque<std::pair<int64_t, MapRelay::iterator>> vRelayExpiration GUARDED_BY(cs_main);
    std::atomic<int64_t> nTimeBestReceived; // Used only to inform the wallet of when we last received a block

public:
    explicit PeerLogicValidation(CConnman* connman, CScheduler &scheduler, bool enable_bip61);

    /**
     * Overridden from CValidationInterface.
     */
    void BlockConnected(const std::shared_ptr<const CBlock>& pblock, const CBlockIndex* pindexConnected, const std::vector<CTransactionRef>& vtxConflicted) override;
    /**
     * Overridden from CValidationInterface.
     */
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    /**
     * Overridden from CValidationInterface.
     */
    void BlockChecked(const CBlock& block, const CValidationState& state) override;
    /**
     * Overridden from CValidationInterface.
     */
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) override;

    /** Initialize a peer by adding it to mapNodeState and pushing a message requesting its version */
    void InitializeNode(CNode* pnode) override;
    /** Handle removal of a peer by updating various state and removing it from mapNodeState */
    void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime) override;
    /**
    * Process protocol messages received from a given node
    *
    * @param[in]   pfrom           The node which we have received messages from.
    * @param[in]   interrupt       Interrupt condition for processing threads
    */
    bool ProcessMessages(CNode* pfrom, std::atomic<bool>& interrupt) override;
    /**
    * Send queued protocol messages to be sent to a give node.
    *
    * @param[in]   pto             The node which we are sending messages to.
    * @return                      True if there is more work to be done
    */
    bool SendMessages(CNode* pto) override EXCLUSIVE_LOCKS_REQUIRED(pto->cs_sendProcessing);

private:
    bool ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, int64_t nTimeReceived, const CChainParams& chainparams, CConnman* connman, const std::atomic<bool>& interruptMsgProc, bool enable_bip61);
    /** If we have extra outbound peers, try to disconnect the one with the oldest block announcement */
    void EvictExtraOutboundPeers(int64_t time_in_seconds);
    /** Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound */
    void CheckForStaleTipAndEvictPeers(const Consensus::Params &consensusParams);
    /** Consider evicting an outbound peer based on the amount of time they've been behind our tip */
    void ConsiderEviction(CNode *pto, int64_t time_in_seconds);

    void sendPingMsg(CNode* pto, const CNetMsgMaker &msgMaker);
    void sendAddrMsg(CNode* pto, int64_t &nNow, const CNetMsgMaker &msgMaker);
    void startBlockSync(CNode* pto, CNodeState &state, const CNetMsgMaker &msgMaker, bool fFetch);
    void sendBlockAnnouncements(CNode* pto, CNodeState &state, const CNetMsgMaker &msgMaker);
    void sendInventory(CNode* pto, int64_t &nNow, const CNetMsgMaker &msgMaker);
    void sendGetdataMsg(CNode* pto, CNodeState &state, int64_t &nNow, bool fFetch, const CNetMsgMaker &msgMaker);
    void feefilter(CNode* pto, const CNetMsgMaker &msgMaker);
    bool checkHeaderSyncTimeout(CNode* pto, CNodeState &state, int64_t &nNow);
    bool checkAndDisconnected(CNode* pto, CNodeState &state, int64_t &nNow);
};

#endif // BITCOIN_NET_PROCESSING_H
