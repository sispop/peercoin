#include <arith_uint256.h>
#include <chain.h>
#include <kernel.h>
#include <bignum.h>
#include <uint256.h>
#include <chainparams.h>
#include "pow.h"
#include <primitives/block.h>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <crypto/ethash/include/ethash/ethash.hpp>
#include <crypto/ethash/helpers.hpp>
#include <openssl/sha.h>
#include <boost/endian/conversion.hpp>

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params)
{
    // If we're at the genesis block or the previous block didn't have a valid proof-of-work, return the minimum difficulty
    if (!pindexLast || !pindexLast->pprev || !pindexLast->IsProofOfWork())
        return params.nPowLimitBits;

    // Get the block headers for the previous two blocks
    const CBlockHeader& prev_header = pindexLast->GetBlockHeader();
    const CBlockHeader* pprev = &prev_header;
    const CBlockHeader& prev_prev_header = pindexLast->pprev->GetBlockHeader();
    const CBlockHeader* pprev_prev = &prev_prev_header;
    // Calculate the time elapsed between the previous two blocks
    int64_t nActualTimespan = pprev->GetBlockTime() - pprev_prev->GetBlockTime();

    // Limit the time elapsed between blocks to 6 hours
    int64_t nTargetTimespan = 6 * 60 * 60;
    if (nActualTimespan < nTargetTimespan / 4)
        nActualTimespan = nTargetTimespan / 4;
    if (nActualTimespan > nTargetTimespan * 4)
        nActualTimespan = nTargetTimespan * 4;

    // Calculate the next difficulty target
    CBigNum nBit;
    nBit.SetCompact(pprev->nBits);
    CBigNum bnNew;
    CBigNum bnOld = nBit;
    bnNew.SetCompact(pindexLast->GetBlockTime() <= params.nPowAllowMinTime ? params.nPowLimitBits : bnOld.GetCompact());
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    // Limit the difficulty adjustment to 400%
    if (bnNew > bnOld * 4)
        bnNew = bnOld * 4;

    // Calculate the KAWPOW hash of the previous block
    uint256 mix_hash;
    const uint256 pow_hash = KAWPOWHash(*pprev, mix_hash);

    // Calculate the hash of the previous block's header using the SHA-512 algorithm
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, &pprev->nVersion, sizeof(pprev->nVersion));
    SHA512_Update(&sha512, &pprev->hashPrevBlock, sizeof(pprev->hashPrevBlock));
    SHA512_Update(&sha512, &pprev->hashMerkleRoot, sizeof(pprev->hashMerkleRoot));
    SHA512_Update(&sha512, &pprev->nTime, sizeof(pprev->nTime));
    SHA512_Update(&sha512, &bnOld, sizeof(bnOld));
    SHA512_Update(&sha512, &pow_hash, sizeof(pow_hash));
    SHA512_Final(hash, &sha512);

    // Use the first 4 bytes of the SHA-512 hash as the new difficulty target
    uint32_t nBits = *reinterpret_cast<uint32_t*>(hash);

    // Convert the target to a compact representation
    CBigNum target;
    target.SetCompact(nBits);

// Limit the difficulty adjustment to 1/4 or 4x of the previous target
CBigNum bnOldCompact = CBigNum(bnOld.GetCompact());
CBigNum bnMin = bnOldCompact / CBigNum(4);

if (bnNew < bnMin) {
bnNew = bnMin;
}
else if (bnNew > bnOld * 4) {
bnNew = bnOld * 4;
}

// Compute the new target

    CBigNum bnNewTarget;
   bnNewTarget.SetCompact(bnNew.GetCompact());

    return bnNewTarget.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}

