//
//  VirgilCrypto+KeyManagement.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public extension VirgilCrypto {
    @objc public func importPrivateKey(fromData data: Data, password: String? = nil) throws -> VirgilPrivateKey {
        let privateKeyData: Data
        if let password = password {
            guard let decryptedPrivateKeyData = VSCKeyPair.decryptPrivateKey(data, privateKeyPassword: password) else {
                throw NSError()
            }
            
            privateKeyData = decryptedPrivateKeyData
        }
        else {
            privateKeyData = data
        }
        
        guard let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: privateKeyData, privateKeyPassword: nil) else {
            throw NSError()
        }
        
        let keyIdentifier = self.computeHash(for: publicKeyData, using: .SHA256)
        
        guard let exportedPrivateKeyData = VSCKeyPair.privateKey(toDER: privateKeyData) else {
            throw NSError()
        }
        
        return VirgilPrivateKey(identifier: keyIdentifier, key: exportedPrivateKeyData)
    }
    
    @objc public func exportPrivateKey(_ privateKey: VirgilPrivateKey, password: String?) throws -> Data {
        let privateKeyData: Data
        if let password = password {
            guard let encryptedPrivateKeyData = VSCKeyPair.encryptPrivateKey(privateKey.key, privateKeyPassword: password) else {
                throw NSError()
            }
            
            privateKeyData = encryptedPrivateKeyData
        }
        else {
            privateKeyData = privateKey.key
        }
        
        return privateKeyData
    }
    
    @objc public func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        guard let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: privateKey.key, privateKeyPassword: nil) else {
            throw NSError()
        }
        
        return VirgilPublicKey(identifier: publicKeyData, key: privateKey.key)
    }
    
    @objc public func exportVirgilPublicKey(_ publicKey: VirgilPublicKey) throws -> Data {
        return publicKey.key
    }
    
    @objc public func importVirgilPublicKey(from data: Data) throws -> VirgilPublicKey {
        guard let publicKeyDER = VSCKeyPair.publicKey(toDER: data) else {
            throw NSError()
        }
        
        let hash = VSCHash(algorithm: .SHA256)
        
        let identifier = hash.hash(publicKeyDER)
        
        return VirgilPublicKey(identifier: identifier, key: publicKeyDER)
    }
}
