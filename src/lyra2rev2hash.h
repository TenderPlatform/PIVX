// Copyright (c) 2018-2018 The BlackBook developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PIVX_LYRA2REV2HASH_H
#define PIVX_LYRA2REV2HASH_H

#include "lyra2rev2/Lyra2.h"
#include "lyra2rev2/sph_blake.h"
#include "lyra2rev2/sph_keccak.h"
#include "lyra2rev2/sph_skein.h"
#include "lyra2rev2/sph_cubehash.h"
#include "lyra2rev2/sph_bmw.h"

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_blake256_context     z_blake;
GLOBAL sph_cubehash256_context  z_cubehash;
GLOBAL sph_keccak256_context    z_keccak;
GLOBAL sph_skein256_context     z_skein;
GLOBAL sph_bmw256_context      z_bmw;

#define fillz() do { \
    sph_blake256_init(&z_blake); \
    sph_cubehash256_init(&z_cubehash); \
    sph_keccak256_init(&z_keccak); \
    sph_skein256_init(&z_skein); \
    sph_bmw256_init(&z_bmw); \
} while (0)

#define ZBLAKE (memcpy(&ctx_blake, &z_blake, sizeof(z_blake)))
#define ZCUBEHASH (memcpy(&ctx_cubehash, &z_cubehash, sizeof(z_cubehash)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZSKEIN (memcpy(&ctx_skein, &z_skein, sizeof(z_skein)))
#define ZBMW (memcpy(&ctx_bmw, &z_bmw, sizeof(z_bmw)))

//<------------------ Signatum LYRA2RE --------------------->
template<typename T1>
inline uint256 lyra2re2_hash(const T1 pbegin, const T1 pend)
{
    sph_blake256_context ctx_blake;
    sph_cubehash256_context ctx_cubehash;
    sph_keccak256_context ctx_keccak;
    sph_skein256_context ctx_skein;
    sph_bmw256_context ctx_bmw;
    static unsigned char pblank[1];

    uint256 hash[2];

    sph_blake256_init(&ctx_blake);
    sph_blake256(&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0])); 
    sph_blake256_close (&ctx_blake, static_cast<void*>(&hash[0]));

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256(&ctx_keccak, static_cast<const void*>(&hash[0]), 32); 
    sph_keccak256_close(&ctx_keccak, static_cast<void*>(&hash[1]));

    sph_cubehash256_init(&ctx_cubehash);
    sph_cubehash256(&ctx_cubehash, static_cast<const void*>(&hash[1]), 32);
    sph_cubehash256_close(&ctx_cubehash, static_cast<void*>(&hash[0]));

    LYRA2(static_cast<void*>(&hash[1]), 32, static_cast<const void*>(&hash[0]), 32, static_cast<const void*>(&hash[0]), 32, 1, 4, 4);

    sph_skein256_init(&ctx_skein);
    sph_skein256(&ctx_skein, static_cast<const void*>(&hash[1]), 32); 
    sph_skein256_close(&ctx_skein, static_cast<void*>(&hash[0]));

    sph_cubehash256_init(&ctx_cubehash);
    sph_cubehash256(&ctx_cubehash, static_cast<const void*>(&hash[0]), 32);
    sph_cubehash256_close(&ctx_cubehash, static_cast<void*>(&hash[1]));

    sph_bmw256_init(&ctx_bmw);
    sph_bmw256(&ctx_bmw, static_cast<const void*>(&hash[1]), 32);
    sph_bmw256_close(&ctx_bmw, static_cast<void*>(&hash[0]));

    return hash[0];
}

#endif // BLACKBOOK_LYRA2REV2HASH_H
