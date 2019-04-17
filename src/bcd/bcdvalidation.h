//
// Created by lh001 on 2019/4/17.
//

#ifndef BITCOINDIAMOND_BCDVALIDATION_H
#define BITCOINDIAMOND_BCDVALIDATION_H

#include <bcd/qtumtransaction.h>
static const size_t MAX_CONTRACT_VOUTS = 1000;

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
