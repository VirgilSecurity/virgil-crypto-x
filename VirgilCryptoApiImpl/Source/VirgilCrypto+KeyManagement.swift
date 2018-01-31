//
//  VirgilCrypto+KeyManagement.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

public extension VirgilCrypto {
    @objc public func importPrivateKey(from data: Data, password: String? = nil) throws -> VirgilPrivateKey {
        let privateKeyData: Data
        if let password = password {
            guard let decryptedPrivateKeyData = VSCKeyPair.decryptPrivateKey(data, privateKeyPassword: password) else {
                throw VirgilCryptoError.decryptPrivateKeyFailed
            }
            
            privateKeyData = decryptedPrivateKeyData
        }
        else {
            privateKeyData = data
        }
        
        guard let privateKeyDER = VSCKeyPair.privateKey(toDER: privateKeyData) else {
            throw VirgilCryptoError.privateKeyToDERFailed
        }
        
        guard let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: privateKeyDER, privateKeyPassword: nil) else {
            throw VirgilCryptoError.extractPublicKeyFailed
        }
        
        let keyIdentifier = self.computeHash(for: publicKeyData, using: .SHA256)
        
        return VirgilPrivateKey(identifier: keyIdentifier, rawKey: privateKeyDER)
    }
    
    @objc public func exportPrivateKey(_ privateKey: VirgilPrivateKey, password: String?) throws -> Data {
        let privateKeyData: Data
        if let password = password {
            guard let encryptedPrivateKeyData = VSCKeyPair.encryptPrivateKey(privateKey.rawKey, privateKeyPassword: password) else {
                throw VirgilCryptoError.encryptPrivateKeyFailed
            }
            
            privateKeyData = encryptedPrivateKeyData
        }
        else {
            privateKeyData = privateKey.rawKey
        }
        
        return privateKeyData
    }
    
    @objc public func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        guard let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: privateKey.rawKey, privateKeyPassword: nil) else {
            throw VirgilCryptoError.extractPublicKeyFailed
        }
        
        let id = self.computeHash(for: publicKeyData, using: .SHA256)
        
        return VirgilPublicKey(identifier: id, rawKey: publicKeyData)
    }
    
    @objc public func exportPublicKey(_ publicKey: VirgilPublicKey) -> Data {
        return publicKey.rawKey
    }
    
    @objc public func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        guard let publicKeyData = VSCKeyPair.publicKey(toDER: data) else {
            throw VirgilCryptoError.publicKeyToDERFailed
        }
        
        let hash = VSCHash(algorithm: .SHA256)
        
        let identifier = hash.hash(publicKeyData)
        
        return VirgilPublicKey(identifier: identifier, rawKey: publicKeyData)
    }
}
