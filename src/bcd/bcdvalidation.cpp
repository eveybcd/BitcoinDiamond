//
// Created by lh001 on 2019/4/17.
//

#include <bcd/bcdvalidation.h>






bool ByteCodeExec::performByteCode(dev::eth::Permanence type){
    for(QtumTransaction& tx : txs){
        //validate VM version
        if(tx.getVersion().toRaw() != VersionVM::GetEVMDefault().toRaw()){
            return false;
        }
        dev::eth::EnvInfo envInfo(BuildEVMEnvironment());
        if(!tx.isCreation() && !globalState->addressInUse(tx.receiveAddress())){
            dev::eth::ExecutionResult execRes;
            execRes.excepted = dev::eth::TransactionException::Unknown;
            result.push_back(ResultExecute{execRes, dev::eth::TransactionReceipt(dev::h256(), dev::u256(), dev::eth::LogEntries()), CTransaction()});
            continue;
        }
        result.push_back(globalState->execute(envInfo, *globalSealEngine.get(), tx, type, OnOpFunc()));
    }
    globalState->db().commit();
    globalState->dbUtxo().commit();
    globalSealEngine.get()->deleteAddresses.clear();
    return true;
}

bool ByteCodeExec::processingResults(ByteCodeExecResult& resultBCE){
    for(size_t i = 0; i < result.size(); i++){
        uint64_t gasUsed = (uint64_t) result[i].execRes.gasUsed;
        if(result[i].execRes.excepted != dev::eth::TransactionException::None){
            if(txs[i].value() > 0){
                CMutableTransaction tx;
                tx.vin.push_back(CTxIn(h256Touint(txs[i].getHashWith()), txs[i].getNVout(), CScript() << OP_SPEND));
                CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
                tx.vout.push_back(CTxOut(CAmount(txs[i].value()), script));
                resultBCE.valueTransfers.push_back(CTransaction(tx));
            }
            resultBCE.usedGas += gasUsed;
        } else {
            if(txs[i].gas() > UINT64_MAX ||
               result[i].execRes.gasUsed > UINT64_MAX ||
               txs[i].gasPrice() > UINT64_MAX){
                return false;
            }
            uint64_t gas = (uint64_t) txs[i].gas();
            uint64_t gasPrice = (uint64_t) txs[i].gasPrice();

            resultBCE.usedGas += gasUsed;
            int64_t amount = (gas - gasUsed) * gasPrice;
            if(amount < 0){
                return false;
            }
            if(amount > 0){
                CScript script(CScript() << OP_DUP << OP_HASH160 << txs[i].sender().asBytes() << OP_EQUALVERIFY << OP_CHECKSIG);
                resultBCE.refundOutputs.push_back(CTxOut(amount, script));
                resultBCE.refundSender += amount;
            }
        }
        if(result[i].tx != CTransaction()){
            resultBCE.valueTransfers.push_back(result[i].tx);
        }
    }
    return true;
}

dev::eth::EnvInfo ByteCodeExec::BuildEVMEnvironment(){
    dev::eth::EnvInfo env;
    CBlockIndex* tip = chainActive.Tip();
    env.setNumber(dev::u256(tip->nHeight + 1));
    env.setTimestamp(dev::u256(block.nTime));
    env.setDifficulty(dev::u256(block.nBits));

    dev::eth::LastHashes lh;
    lh.resize(256);
    for(int i=0;i<256;i++){
        if(!tip)
            break;
        lh[i]= uintToh256(*tip->phashBlock);
        tip = tip->pprev;
    }
    env.setLastHashes(std::move(lh));
    env.setGasLimit(blockGasLimit);
    if(block.IsProofOfStake()){
        env.setAuthor(EthAddrFromScript(block.vtx[1]->vout[1].scriptPubKey));
    }else {
        env.setAuthor(EthAddrFromScript(block.vtx[0]->vout[0].scriptPubKey));
    }
    return env;
}

dev::Address ByteCodeExec::EthAddrFromScript(const CScript& script){
    CTxDestination addressBit;
    txnouttype txType=TX_NONSTANDARD;
    if(ExtractDestination(script, addressBit, &txType)){
        if ((txType == TX_PUBKEY || txType == TX_PUBKEYHASH) &&
            addressBit.type() == typeid(CKeyID)){
            CKeyID addressKey(boost::get<CKeyID>(addressBit));
            std::vector<unsigned char> addr(addressKey.begin(), addressKey.end());
            return dev::Address(addr);
        }
    }
    //if not standard or not a pubkey or pubkeyhash output, then return 0
    return dev::Address();
}