//
// Copyright (C) 2015-2021 Virgil Security Inc.
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

import Foundation
import VirgilCryptoFoundation

// MARK: - Conversion extension
extension KeyPairType {
    internal init(from key: Key) throws {
        let algInfo = key.algInfo()
        let algId = algInfo.algId()

        if algId == .compoundKey {
            guard let compoundInfo = algInfo as? CompoundKeyAlgInfo else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            let cipherAlgId = compoundInfo.cipherAlgInfo().algId()
            let signerAlgId = compoundInfo.signerAlgInfo().algId()

            if cipherAlgId == .hybridKey && signerAlgId == .hybridKey {
                guard let cipherHybrid = compoundInfo.cipherAlgInfo() as? HybridKeyAlgInfo,
                      let signerHybrid = compoundInfo.signerAlgInfo() as? HybridKeyAlgInfo else {
                    throw VirgilCryptoError.unknownCompoundKey
                }

                if cipherHybrid.firstKeyAlgInfo().algId() == .curve25519
                    && cipherHybrid.secondKeyAlgInfo().algId() == .mlKem768
                    && signerHybrid.firstKeyAlgInfo().algId() == .ed25519
                    && signerHybrid.secondKeyAlgInfo().algId() == .falcon {
                    self = .curve25519Round5Ed25519Falcon
                } else {
                    throw VirgilCryptoError.unknownCompoundKey
                }
            } else if cipherAlgId == .curve25519 && signerAlgId == .ed25519 {
                self = .curve25519Ed25519
            } else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            return
        }

        if algId == .hybridKey {
            guard let hybridInfo = algInfo as? HybridKeyAlgInfo else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            if hybridInfo.firstKeyAlgInfo().algId() == .curve25519
                && hybridInfo.secondKeyAlgInfo().algId() == .mlKem768 {
                self = .curve25519Round5
            } else {
                throw VirgilCryptoError.unknownCompoundKey
            }

            return
        }

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
            return (.curve25519, .mlKem768)
        case .curve25519, .ed25519, .rsa2048, .rsa4096, .rsa8192, .secp256r1:
            throw VirgilCryptoError.keyIsNotCompound
        }
    }
}
