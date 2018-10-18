BitcoinDiamond version *1.1.0* is now available from:

  <https://github.com/eveybcd/BitcoinDiamond/releases/tag/v1.1.0>

This is a new major version release, including various bugfixes and
performance improvements.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/eveybcd/BitcoinDiamond/issues>

This release includes the following features and fixes:
 - Support testnet & regtest.
 - Fix relay block data limited 4MB to 32MB.
 - Add `getchaintxstats` RPC.
 - Update `getblock` RPC.
 - Update LevelDB to 1.20.
 - Update boost to 1.66.

1.1.0 Change log
=================

- `024f1bc` Enlarge block-max-size & block-max-weight options of miner default policy
- `68b7bcd` Fix LXC network problems
- `2084645` fix relay block data limited 4MB to 32MB
- `a403588` update blockindex to string powhash for bcd block
- `f69fdce` Remove Clang workaround for Boost 1.46
- `1b2d47f` Fix CVE-2018-12356 by hardening the regex
- `3cce6bc` Allow multiple names for parameters
- `0a7ed1d` Remove Clang workaround for Boost 1.46
- `29f7a20` Allow multiple names for parameters
- `97ab3c0` Remove using namespace from rpc
- `c65634f` getblock provides detailed transaction information
- `d2099b8`	Update to LevelDB 1.20
- `99c1fb8`	Add getchaintxstats RPC
- `b36a9a2`	update config.guess & config.sub
- `a259cc8`	change testnet dns seed
- `0299007` Support regtest mode
- `c69cda4` Add testnet dns seed
- `2f0370b` Calculate minimum amount of total work of the new testnet blockchain
- `a9f2729` add Dockerfile
- `73b5b64` fix powhash string
- `bd6d679` Make boost::multi_index comparators const This fixes compatibility with boost 1.66
- `b254eb9` Add pow limit for bcd  first 72 blocks  (testnet)
- `16cc4ba` Add consensus of block reward for testnet
- `0e85a71` add check block height high than bcd fork height