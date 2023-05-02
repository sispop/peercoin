// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>
#include <crypto/ethash/include/ethash/ethash.hpp>
#include <hash.h>
#include <tinyformat.h>
#include <openssl/sha.h>

/*uint256 CBlockHeader::GetHash() const
{
    CBlockHeader tmp(*this);
    tmp.nFlags = 0;
    return SerializeHash(tmp);
}*/

constexpr int PROGPOW_HEADER_SIZE = 140;

/*uint256 CBlockHeader::GetValidationHash(uint256& mix_hash) const
{
    unsigned char header[PROGPOW_HEADER_SIZE];
    std::memcpy(header, &nVersion, sizeof(nVersion));
    std::memcpy(header + sizeof(nVersion), &hashPrevBlock, sizeof(hashPrevBlock));
    std::memcpy(header + sizeof(nVersion) + sizeof(hashPrevBlock), &hashMerkleRoot, sizeof(hashMerkleRoot));
    std::memcpy(header + sizeof(nVersion) + sizeof(hashPrevBlock) + sizeof(hashMerkleRoot), &nTime, sizeof(nTime));
    std::memcpy(header + sizeof(nVersion) + sizeof(hashPrevBlock) + sizeof(hashMerkleRoot) + sizeof(nTime), &nBits, sizeof(nBits));
    std::memcpy(header + sizeof(nVersion) + sizeof(hashPrevBlock) + sizeof(hashMerkleRoot) + sizeof(nTime) + sizeof(nBits), mix_hash.begin(), sizeof(uint256));

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(header, PROGPOW_HEADER_SIZE, hash);

    uint256 ret;
    std::memcpy(&ret, hash, sizeof(ret));
    return ret;
}*/

/*uint256 CBlockHeader::GetValidationHash(uint256& mix_hash) const
{
        return KAWPOWHash(*this, mix_hash);
}*/

uint256 CBlockHeader::GetHash() const
{
    CKAWPOWInput input{*this};

    return SerializeHash(input);
}

/*uint256 CBlockHeader::GetHash() const {
    // Calculate the KAWPOW hash of the block header
    uint256 mix_hash;
    const uint256 pow_hash = KAWPOWHash(*this, mix_hash);

    // Calculate the hash of the block header using the SHA-512 algorithm
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, &nVersion, sizeof(nVersion));
    SHA512_Update(&sha512, &hashPrevBlock, sizeof(hashPrevBlock));
    SHA512_Update(&sha512, &hashMerkleRoot, sizeof(hashMerkleRoot));
    SHA512_Update(&sha512, &nTime, sizeof(nTime));
    SHA512_Update(&sha512, &nBits, sizeof(nBits));
    SHA512_Update(&sha512, &pow_hash, sizeof(pow_hash));
    SHA512_Update(&sha512, &nNonce, sizeof(nNonce));
    SHA512_Final(hash, &sha512);

    // Take the first 32 bytes of the SHA-512 hash as the block hash
    uint256 result;
    memcpy(result.begin(), hash, 32);
    return result;
}
*/
/*
uint256 CBlockHeader::GetHash() const
{
    uint256 mixHash;
    uint256 powHash = KAWPOWHash(*this, mixHash);

    // Concatenate the block header fields into a single buffer
    CHashWriter writer(SER_GETHASH, PROTOCOL_VERSION);
    writer << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << powHash;

    // Return the SHA-256 hash of the concatenated buffer
    return writer.GetHash();
}
*/
std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nFlags=%08x, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        nFlags, vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
