// Copyright (c) 2019 The BCD Core developers

#include <network/net_cnode_state.h>
#include <network/net_processing.h>



bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == nullptr)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    for (const QueuedBlock& queue : state->vBlocksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}


