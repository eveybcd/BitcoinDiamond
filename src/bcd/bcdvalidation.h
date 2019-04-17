//
// Created by lh001 on 2019/4/17.
//

#ifndef BITCOINDIAMOND_BCDVALIDATION_H
#define BITCOINDIAMOND_BCDVALIDATION_H

#include <amount.h>
#include <bcd/qtumtransaction.h>
#include <primitives/transaction.h>
#include <primitives/block.h>
#include <bcd/qtumstate.h>
#include <chain.h>

static const size_t MAX_CONTRACT_VOUTS = 1000;
extern std::unique_ptr<QtumState> globalState;
extern std::shared_ptr<dev::eth::SealEngineFace> globalSealEngine;


struct ByteCodeExecResult{
    uint64_t usedGas = 0;
    CAmount refundSender = 0;
    std::vector<CTxOut> refundOutputs;
    std::vector<CTransaction> valueTransfers;
};

class ByteCodeExec {

public:

    ByteCodeExec(const CBlock& _block, std::vector<QtumTransaction> _txs, const uint64_t _blockGasLimit) : txs(_txs), block(_block), blockGasLimit(_blockGasLimit) {}

    bool performByteCode(dev::eth::Permanence type = dev::eth::Permanence::Committed);

    bool processingResults(ByteCodeExecResult& result);

    std::vector<ResultExecute>& getResult(){ return result; }

private:

    dev::eth::EnvInfo BuildEVMEnvironment();

    dev::Address EthAddrFromScript(const CScript& scriptIn);

    std::vector<QtumTransaction> txs;

    std::vector<ResultExecute> result;

    const CBlock& block;

    const uint64_t blockGasLimit;

};
#endif //BITCOINDIAMOND_BCDVALIDATION_H
