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
    internal func importInternalPrivateKey(from data: Data) throws -> VirgilCryptoFoundation.PrivateKey {
        let keyProvider = KeyProvider()
        
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()
        
        return try keyProvider.importPrivateKey(keyData: data)
    }
    
    internal func importInternalPublicKey(from data: Data) throws -> VirgilCryptoFoundation.PublicKey {
        let keyProvider = KeyProvider()
        
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()
        
        return try keyProvider.importPublicKey(keyData: data)
    }
    
    /// Imports private key from DER or PEM format
    ///
    /// - Parameter data: Private key in DER or PEM format
    /// - Returns: VirgilKeyPair
    /// - Throws: Rethrows from KeyProvider
    @objc open func importPrivateKey(from data: Data) throws -> VirgilKeyPair {
        let privateKey = try importInternalPrivateKey(from: data)

        let keyType: KeyPairType

        if privateKey.algId() == .rsa {
            keyType = try KeyPairType(fromRsaBitLen: privateKey.keyBitlen())
        }
        else {
            keyType = try KeyPairType(from: privateKey.algId())
        }

        let publicKey = privateKey.extractPublicKey()
        
        let privateKeyData = try self.exportInternalPrivateKey(privateKey)
        let publicKeyData = try self.exportInternalPublicKey(publicKey)

        let keyId = try self.computePublicKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilKeyPair(privateKey: VirgilPrivateKey(identifier: keyId, privateKey: privateKeyData, keyType: keyType),
                             publicKey: VirgilPublicKey(identifier: keyId, publicKey: publicKeyData, keyType: keyType))
    }

    internal func exportInternalPrivateKey(_ privateKey: VirgilCryptoFoundation.PrivateKey) throws -> Data {
        let serializer = KeyAsn1Serializer()
        serializer.setupDefaults()

        return try serializer.serializePrivateKey(privateKey: privateKey)
    }

    /// Extracts public key from private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Public Key that matches passed Private Key
    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        let privateKeyInternal = try self.importInternalPrivateKey(from: privateKey.privateKey)
        let publicKey = privateKeyInternal.extractPublicKey()
        let publicKeyData = try self.exportInternalPublicKey(publicKey)
        
        return VirgilPublicKey(identifier: privateKey.identifier,
                               publicKey: publicKeyData,
                               keyType: privateKey.keyType)
    }
    
    internal func exportInternalPublicKey(_ publicKey: VirgilCryptoFoundation.PublicKey) throws -> Data {
        let serializer = KeyAsn1Serializer()
        serializer.setupDefaults()

        return try serializer.serializePublicKey(publicKey: publicKey)
    }

    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key in DER or PEM format
    /// - Returns: Imported Public Key
    /// - Throws: Rethrows from KeyProvider
    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()

        let publicKey = try keyProvider.importPublicKey(keyData: data)

        let keyType: KeyPairType

        if publicKey.algId() == .rsa {
            keyType = try KeyPairType(fromRsaBitLen: publicKey.keyBitlen())
        }
        else {
            keyType = try KeyPairType(from: publicKey.algId())
        }
        
        let publicKeyData = try self.exportInternalPublicKey(publicKey)

        let keyId = try self.computePublicKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPublicKey(identifier: keyId, publicKey: publicKeyData, keyType: keyType)
    }
    
    @objc public func exportPublicKey(_ publicKey: VirgilPublicKey) throws -> Data {
        return publicKey.publicKey
    }
    
    @objc public func exportPrivateKey(_ privateKey: VirgilPrivateKey) throws -> Data {
        return privateKey.privateKey
    }
}
