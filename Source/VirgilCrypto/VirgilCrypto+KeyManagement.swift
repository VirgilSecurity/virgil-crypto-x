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

// MARK: - Extension for key management
extension VirgilCrypto {
    private func importInternalPrivateKey(from data: Data) throws -> VirgilCryptoFoundation.PrivateKey {
        let keyProvider = KeyProvider()

        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        return try keyProvider.importPrivateKey(keyData: data)
    }

    private func importInternalPublicKey(from data: Data) throws -> VirgilCryptoFoundation.PublicKey {
        let keyProvider = KeyProvider()

        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        return try keyProvider.importPublicKey(keyData: data)
    }

    /// Imports private key from DER or PEM format
    ///
    /// - Parameter data: Private key in DER or PEM format
    /// - Returns: VirgilKeyPair
    /// - Throws: Rethrows from `KeyProvider`
    @objc open func importPrivateKey(from data: Data) throws -> VirgilKeyPair {
        let privateKey = try self.importInternalPrivateKey(from: data)

        let keyType = try KeyPairType(from: privateKey)

        let publicKey = privateKey.extractPublicKey()

        let keyId = try self.computePublicKeyIdentifier(publicKey: publicKey)

        return VirgilKeyPair(privateKey: VirgilPrivateKey(identifier: keyId, key: privateKey, keyType: keyType),
                             publicKey: VirgilPublicKey(identifier: keyId, key: publicKey, keyType: keyType))
    }

    internal func exportInternalPrivateKey(_ privateKey: VirgilCryptoFoundation.PrivateKey) throws -> Data {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        return try keyProvider.exportPrivateKey(privateKey: privateKey)
    }

    /// Extracts public key from private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Public Key that matches passed Private Key
    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        let publicKey = privateKey.key.extractPublicKey()

        return VirgilPublicKey(identifier: privateKey.identifier,
                               key: publicKey,
                               keyType: privateKey.keyType)
    }

    internal func exportInternalPublicKey(_ publicKey: VirgilCryptoFoundation.PublicKey) throws -> Data {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        return try keyProvider.exportPublicKey(publicKey: publicKey)
    }

    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key in DER or PEM format
    /// - Returns: Imported Public Key
    /// - Throws: Rethrows from `KeyProvider`
    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        let publicKey = try keyProvider.importPublicKey(keyData: data)

        let keyType = try KeyPairType(from: publicKey)

        let keyId = try self.computePublicKeyIdentifier(publicKey: publicKey)

        return VirgilPublicKey(identifier: keyId, key: publicKey, keyType: keyType)
    }

    /// Exports public key
    ///
    /// - Parameter publicKey: Public key
    /// - Returns: Exported public key
    /// - Throws: Rethrows from `KeyProvider`
    @objc public func exportPublicKey(_ publicKey: VirgilPublicKey) throws -> Data {
        return try self.exportInternalPublicKey(publicKey.key)
    }

    /// Export private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Exported private key
    /// - Throws: Rethrows from `KeyProvider`
    @objc public func exportPrivateKey(_ privateKey: VirgilPrivateKey) throws -> Data {
        return try self.exportInternalPrivateKey(privateKey.key)
    }
}
