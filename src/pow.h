#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H

#include <consensus/params.h>
#include <primitives/block.h>

/** Returns the next target difficulty after the current block. */
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params);

/** Checks whether a block hash satisfies the proof-of-work requirement specified by nBits. */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params);

/** Computes the KAWPOW hash and mix for the given block header. Returns the KAWPOW hash. */
uint256 KAWPOWHash(const CBlockHeader& header, uint256& mix);

#endif // BITCOIN_POW_H

