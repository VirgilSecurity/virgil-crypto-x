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

import Foundation
import VirgilCryptoFoundation

// MARK: - Extension for key management
extension VirgilCrypto {
    @objc open func importPrivateKey(from data: Data) throws -> VirgilPrivateKey {
        let keyProvider = KeyProvider()
        
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()
        
        let err = ErrorCtx()
        
        let privateKey = keyProvider.importPrivateKey(pkcs8Data: data, error: err)
        
        try err.error()
        
        let keyType: KeyPairType
        
        if privateKey.algId() == .rsa {
            switch privateKey.keyBitlen() {
            case 2048: keyType = .rsa2048
            case 4096: keyType = .rsa4096
            case 8192: keyType = .rsa8192
            default: throw NSError() // FIXME
            }
        }
        else {
            keyType = try KeyPairType(from: privateKey.algId())
        }

        let keyId = try self.computeKeyIdentifier(privateKey: privateKey)

        return VirgilPrivateKey(identifier: keyId, privateKey: privateKey, keyType: keyType)
    }
    
    /// Exports private key to DER foramt
    ///
    /// WARNING: Consider using export with password
    ///
    /// - Parameter privateKey: Private key to export
    /// - Returns: Private key in DER format
    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey) throws -> Data {
        let pkcs8DerSerializer = Pkcs8DerSerializer()
        try pkcs8DerSerializer.setupDefaults()
        
        return try pkcs8DerSerializer.serializePrivateKey(privateKey: privateKey.privateKey)
    }
    
    /// Extracts public key from private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Public Key that matches passed Private Key
    /// - Throws: VirgilCryptoError.extractPublicKeyFailed, if extraction failed
    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        return VirgilPublicKey(identifier: privateKey.identifier, publicKey: privateKey.privateKey.extractPublicKey(), keyType: privateKey.keyType)
    }
    
    /// Exports public key in DER format
    ///
    /// - Parameter publicKey: PublicKey to export
    /// - Returns: Exported public key in DER format
    @objc open func exportPublicKey(_ publicKey: VirgilPublicKey) throws -> Data {
        let pkcs8DerSerializer = Pkcs8DerSerializer()
        try pkcs8DerSerializer.setupDefaults()
        
        return try pkcs8DerSerializer.serializePublicKey(publicKey: publicKey.publicKey)
    }
    
    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key in DER or PEM format
    /// - Returns: Imported Public Key
    /// - Throws: VirgilCryptoError.publicKeyToDERFailed, if public key is corrupted and conversion to DER failed
    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        let keyProvider = KeyProvider()
        keyProvider.setRandom(random: self.rng)
        try keyProvider.setupDefaults()
        
        let err = ErrorCtx()
        
        let publicKey = keyProvider.importPublicKey(pkcs8Data: data, error: err)
        
        try err.error()
        
        let keyType: KeyPairType
        
        if publicKey.algId() == .rsa {
            switch publicKey.keyBitlen() {
            case 2048: keyType = .rsa2048
            case 4096: keyType = .rsa4096
            case 8192: keyType = .rsa8192
            default: throw NSError() // FIXME
            }
        }
        else {
            keyType = try KeyPairType(from: publicKey.algId())
        }
        
        let keyId = try self.computeKeyIdentifier(publicKey: publicKey)

        return VirgilPublicKey(identifier: keyId, publicKey: publicKey, keyType: keyType)
    }
}
