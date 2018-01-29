//
//  VirgilCrypto+KeyGeneration.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public extension VirgilCrypto {
    private func wrapKeyPair(keyPair: VSCKeyPair) throws -> VirgilKeyPair {
         guard let publicKeyDER = VSCKeyPair.publicKey(toDER: keyPair.publicKey()) else {
            throw VirgilCryptoError.publicKeyToDERFailed
         }
        
        guard let privateKeyDER = VSCKeyPair.privateKey(toDER: keyPair.privateKey()) else {
            throw VirgilCryptoError.privateKeyToDERFailed
        }
        
         let hash = VSCHash(algorithm: .SHA256)
         let keyPairId = hash.hash(publicKeyDER)
        
        let privateKey = VirgilPrivateKey(identifier: keyPairId, rawKey: privateKeyDER)
        let publicKey = VirgilPublicKey(identifier: keyPairId, rawKey: publicKeyDER)
        
        return VirgilKeyPair(privateKey: privateKey, publicKey: publicKey)
    }
    
    @objc public func generateMultipleKeyPairs(numberOfKeyPairs: UInt) throws -> [VirgilKeyPair] {
        return try VSCKeyPair
            .generateMultipleKeys(numberOfKeyPairs, keyPairType: self.defaultKeyType)
            .map({ try self.wrapKeyPair(keyPair: $0) })
    }
    
    @objc public func generateKeyPair() throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType)
    }
    
    @objc public func generateKeyPair(ofType type: VSCKeyType) throws -> VirgilKeyPair {
        let keyPair = VSCKeyPair(keyPairType: type, password: nil)
        
        return try self.wrapKeyPair(keyPair: keyPair)
    }
}
