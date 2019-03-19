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
    /// Imports private key from DER or PEM format
    ///
    /// - Parameter data: Private key in DER or PEM format
    /// - Returns: VirgilKeyPair
    /// - Throws: Rethrows from KeyProvider, Pkcs8DerSerializer
    @objc open func importPrivateKey(from data: Data) throws -> VirgilKeyPair {
        let keyProvider = KeyProvider()

        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        let privateKey = try keyProvider.importPrivateKey(pkcs8Data: data)

        let keyType: KeyPairType

        if privateKey.algId() == .rsa {
            keyType = try KeyPairType(fromRsaBitLen: privateKey.keyBitlen())
        }
        else {
            keyType = try KeyPairType(from: privateKey.algId())
        }

        let publicKey = privateKey.extractPublicKey()

        let keyId = try self.computePublicKeyIdentifier(publicKey: publicKey)

        return VirgilKeyPair(privateKey: VirgilPrivateKey(identifier: keyId, privateKey: privateKey, keyType: keyType),
                             publicKey: VirgilPublicKey(identifier: keyId, publicKey: publicKey, keyType: keyType))
    }

    /// Exports private key to DER foramt
    ///
    /// - Parameter privateKey: Private key to export
    /// - Returns: Private key in DER format
    /// - Throws: Rethrows from Pkcs8DerSerializer
    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey) throws -> Data {
        let pkcs8DerSerializer = Pkcs8DerSerializer()
        pkcs8DerSerializer.setupDefaults()

        return try pkcs8DerSerializer.serializePrivateKey(privateKey: privateKey.privateKey)
    }

    /// Extracts public key from private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Public Key that matches passed Private Key
    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) -> VirgilPublicKey {
        return VirgilPublicKey(identifier: privateKey.identifier,
                               publicKey: privateKey.privateKey.extractPublicKey(),
                               keyType: privateKey.keyType)
    }

    /// Exports public key in DER format
    ///
    /// - Parameter publicKey: PublicKey to export
    /// - Returns: Exported public key in DER format
    /// - Throws: Rethrows from Pkcs8DerSerializer
    @objc open func exportPublicKey(_ publicKey: VirgilPublicKey) throws -> Data {
        let pkcs8DerSerializer = Pkcs8DerSerializer()
        pkcs8DerSerializer.setupDefaults()

        return try pkcs8DerSerializer.serializePublicKey(publicKey: publicKey.publicKey)
    }

    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key in DER or PEM format
    /// - Returns: Imported Public Key
    /// - Throws: Rethrows from KeyProvider, Pkcs8DerSerializer
    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        let publicKey = try keyProvider.importPublicKey(pkcs8Data: data)

        let keyType: KeyPairType

        if publicKey.algId() == .rsa {
            keyType = try KeyPairType(fromRsaBitLen: publicKey.keyBitlen())
        }
        else {
            keyType = try KeyPairType(from: publicKey.algId())
        }

        let keyId = try self.computePublicKeyIdentifier(publicKey: publicKey)

        return VirgilPublicKey(identifier: keyId, publicKey: publicKey, keyType: keyType)
    }
}
