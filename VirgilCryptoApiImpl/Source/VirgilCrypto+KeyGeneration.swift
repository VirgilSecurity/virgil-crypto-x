//
//  VirgilCrypto+KeyGeneration.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

public extension VirgilCrypto {
    private func wrapKeyPair(keyPair: KeyPair) throws -> VirgilKeyPair {
         guard let publicKeyDER = KeyPair.publicKey(toDER: keyPair.publicKey()) else {
            throw VirgilCryptoError.publicKeyToDERFailed
         }

        guard let privateKeyDER = KeyPair.privateKey(toDER: keyPair.privateKey()) else {
            throw VirgilCryptoError.privateKeyToDERFailed
        }

         let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyDER)

        let privateKey = VirgilPrivateKey(identifier: identifier, rawKey: privateKeyDER)
        let publicKey = VirgilPublicKey(identifier: identifier, rawKey: publicKeyDER)

        return VirgilKeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    @objc public func generateMultipleKeyPairs(numberOfKeyPairs: UInt) throws -> [VirgilKeyPair] {
        return try KeyPair
            .generateMultipleKeys(numberOfKeyPairs, keyPairType: self.defaultKeyType)
            .map({ try self.wrapKeyPair(keyPair: $0) })
    }

    @objc public func generateKeyPair() throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType)
    }

    @objc public func generateKeyPair(ofType type: VSCKeyType) throws -> VirgilKeyPair {
        let keyPair = KeyPair(keyPairType: type, password: nil)

        return try self.wrapKeyPair(keyPair: keyPair)
    }
}
