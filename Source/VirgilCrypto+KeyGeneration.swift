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

/// MARK: - Extension for key generation
extension VirgilCrypto {
    /// Computes public key identifier
    ///
    /// - Note: Takes first 8 bytes of SHA512 of public key DER if useSHA256Fingerprints=false
    ///         and SHA256 of public key der if useSHA256Fingerprints=true
    ///
    /// - Parameter publicKey: PublicKey
    /// - Returns: Public key identifier
    /// - Throws: Rethrows from Pkcs8DerSerializer
    @objc open func computePublicKeyIdentifier(publicKey: VirgilCryptoFoundation.PublicKey) throws -> Data {
        let pkcs8DerSerializer = Pkcs8DerSerializer()
        pkcs8DerSerializer.setupDefaults()

        let publicKeyDER = try pkcs8DerSerializer.serializePublicKey(publicKey: publicKey)

        if self.useSHA256Fingerprints {
            return self.computeHash(for: publicKeyDER, using: .sha256)
        }
        else {
            return self.computeHash(for: publicKeyDER, using: .sha512).subdata(in: 0..<8)
        }
    }

    private func generateKeyPair(ofType type: KeyPairType, using rng: Random) throws -> VirgilKeyPair {
        let keyProvider = KeyProvider()

        if let rsaLen = type.rsaBitLen {
            keyProvider.setRsaParams(bitlen: rsaLen)
        }

        keyProvider.setRandom(random: rng)
        try keyProvider.setupDefaults()

        let algId = type.algId

        let privateKey = try keyProvider.generatePrivateKey(algId: algId)

        let publicKey = privateKey.extractPublicKey()

        let keyId = try self.computePublicKeyIdentifier(publicKey: publicKey)

        return VirgilKeyPair(privateKey: VirgilPrivateKey(identifier: keyId, privateKey: privateKey, keyType: type),
                             publicKey: VirgilPublicKey(identifier: keyId, publicKey: publicKey, keyType: type))
    }

    /// Generates KeyPair of default type using seed
    ///
    /// - Parameter seed: random value used to generate key
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyProvider
    @objc open func generateKeyPair(usingSeed seed: Data) throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType, usingSeed: seed)
    }

    /// Generates KeyPair of default type using seed
    ///
    /// - Parameters:
    ///   - type: KeyPair type
    ///   - seed: random value used to generate key
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyProvider
    @objc open func generateKeyPair(ofType type: KeyPairType, usingSeed seed: Data) throws -> VirgilKeyPair {
        guard KeyMaterialRng.keyMaterialLenMin...KeyMaterialRng.keyMaterialLenMax ~= seed.count else {
            throw VirgilCryptoError.invalidSeedSize
        }

        let seedRng = KeyMaterialRng()

        seedRng.resetKeyMaterial(keyMaterial: seed)

        return try self.generateKeyPair(ofType: type, using: seedRng)
    }

    /// Generates KeyPair of default type
    ///
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyPair
    @objc open func generateKeyPair() throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType)
    }

    /// Generates KeyPair of given type
    ///
    /// - Parameter type: KeyPair type
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyProvider
    @objc open func generateKeyPair(ofType type: KeyPairType) throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: type, using: self.rng)
    }
}
