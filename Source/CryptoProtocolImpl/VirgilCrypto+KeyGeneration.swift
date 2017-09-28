//
//  VirgilCrypto+KeyGeneration.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

public extension VirgilCrypto {
    private func wrapKeyPair(keyPair: VSCKeyPair) -> VirgilKeyPair {
        let keyPairId = self.computeSHA256(for: keyPair.publicKey())
        
        let privateKey = VirgilPrivateKey(identifier: keyPairId, key: keyPair.privateKey())
        let publicKey = VirgilPublicKey(identifier: keyPairId, key: keyPair.publicKey())
        
        return VirgilKeyPair(privateKey: privateKey, publicKey: publicKey)
    }
    
    @objc public func generateMultipleKeyPairs(numberOfKeyPairs: UInt) -> [VirgilKeyPair] {
        return VSCKeyPair
            .generateMultipleKeys(numberOfKeyPairs, keyPairType: self.defaultKeyType)
            .map({ self.wrapKeyPair(keyPair: $0) })
    }
    
    @objc public func generateKeyPair() -> VirgilKeyPair {
        return self.generateKeyPair(ofType: self.defaultKeyType)
    }
    
    @objc public func generateKeyPair(ofType type: VSCKeyType) -> VirgilKeyPair {
        let keyPair = VSCKeyPair(keyPairType: type, password: nil)
        
        return self.wrapKeyPair(keyPair: keyPair)
    }
}
