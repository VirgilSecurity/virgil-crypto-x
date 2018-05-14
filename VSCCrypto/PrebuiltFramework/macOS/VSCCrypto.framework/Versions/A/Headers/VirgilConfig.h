/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */


#ifndef VIRGIL_CRYPTO_CONFIG
#define VIRGIL_CRYPTO_CONFIG

/**
 * Contains conditional macroses, that was used during library build.
 */

/**
 * On/Off status of the feature: C++ streams.
 */
#define VIRGIL_CRYPTO_FEATURE_STREAM_IMPL 1

/**
 * On/Off status of the feature: Pythia.
 */
#define VIRGIL_CRYPTO_FEATURE_PYTHIA 0

/**
 * On/Off status of the Pythia multhi-threading.
 */
#define VIRGIL_CRYPTO_FEATURE_PYTHIA_MT 1


namespace virgil {
namespace crypto {

class VirgilConfig {
public:
    /**
     * @brief Runtime equiavalent of VIRGIL_CRYPTO_FEATURE_STREAM_IMPL
     */
    static bool hasFeatureStreamImpl();

    /**
     * @brief Runtime equiavalent of VIRGIL_CRYPTO_FEATURE_PYTHIA
     */
    static bool hasFeaturePythiaImpl();

    /**
     * @brief Runtime equiavalent of VIRGIL_CRYPTO_FEATURE_PYTHIA_MT
     */
    static bool hasFeaturePythiaMultiThread();

};

} // crypto
} // virgil

#endif /* VIRGIL_CRYPTO_CONFIG */
