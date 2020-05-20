//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import VirgilCryptoFoundation

// MARK: - Conversion extension
extension KeyPairType {
    internal init(from key: Key) throws {
        let keyInfo = KeyInfo(algInfo: key.algInfo())

        if keyInfo.isCompound() {
            if keyInfo.compoundHybridCipherFirstKeyAlgId() == .curve25519
                && keyInfo.compoundHybridCipherSecondKeyAlgId() == .round5Nd1cca5d
                && keyInfo.compoundHybridSignerFirstKeyAlgId() == .ed25519
                && keyInfo.compoundHybridSignerSecondKeyAlgId() == .falcon {
                self = .curve25519Round5Ed25519Falcon
            }
            else if keyInfo.compoundCipherAlgId() == .curve25519
                && keyInfo.compoundSignerAlgId() == .ed25519 {
                self = .curve25519Ed25519
            }
            else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            return
        }

        if keyInfo.isHybrid() {
            if keyInfo.hybridFirstKeyAlgId() == .curve25519 && keyInfo.hybridSecondKeyAlgId() == .round5Nd1cca5d {
                self = .curve25519Round5
            }
            else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            return
        }

        let algId = keyInfo.algId()

        if algId == .rsa {
            self = try KeyPairType(fromRsaBitLen: key.bitlen())
            return
        }

        switch algId {
        case .ed25519:
            self = .ed25519
        case .curve25519:
            self = .curve25519
        case .secp256r1:
            self = .secp256r1
        default:
            throw VirgilCryptoError.unknownAlgId
        }
    }

    internal func getAlgId() throws -> AlgId {
        switch self {
        case .ed25519:
            return .ed25519
        case .curve25519:
            return .curve25519
        case .secp256r1:
            return .secp256r1
        case .rsa2048, .rsa4096, .rsa8192:
            return .rsa
        case .curve25519Round5Ed25519Falcon, .curve25519Ed25519, .curve25519Round5:
            throw VirgilCryptoError.compundKeyShouldBeGeneratedDirectly
        }
    }

    internal var isHybrid: Bool {
        switch self {
        case .curve25519Ed25519, .curve25519Round5Ed25519Falcon, .curve25519Round5:
            return true
        case .curve25519, .ed25519, .rsa2048, .rsa4096, .rsa8192, .secp256r1:
            return false
        }
    }

    internal var isCompound: Bool {
        switch self {
        case .curve25519Ed25519, .curve25519Round5Ed25519Falcon:
            return true
        case .curve25519, .ed25519, .rsa2048, .rsa4096, .rsa8192, .secp256r1, .curve25519Round5:
            return false
        }
    }

    internal func getSignerKeysAlgIds() throws -> (first: AlgId, second: AlgId) {
        switch self {
        case .curve25519Round5:
            return (.none, .none)
        case .curve25519Ed25519:
            return (.ed25519, .none)
        case .curve25519Round5Ed25519Falcon:
            return (.ed25519, .falcon)
        case .curve25519, .ed25519, .rsa2048, .rsa4096, .rsa8192, .secp256r1:
            throw VirgilCryptoError.keyIsNotCompound
        }
    }

    internal func getCipherKeysAlgIds() throws -> (first: AlgId, second: AlgId) {
        switch self {
        case .curve25519Ed25519:
            return (.curve25519, .none)
        case .curve25519Round5Ed25519Falcon, .curve25519Round5:
            return (.curve25519, .round5Nd1cca5d)
        case .curve25519, .ed25519, .rsa2048, .rsa4096, .rsa8192, .secp256r1:
            throw VirgilCryptoError.keyIsNotCompound
        }
    }
}
