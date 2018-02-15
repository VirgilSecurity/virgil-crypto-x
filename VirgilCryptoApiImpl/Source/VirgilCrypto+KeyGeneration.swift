//
//  VirgilCrypto+KeyGeneration.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

// MARK: - Extension for key generation
extension VirgilCrypto {
    /// Generates mutiple key pairs of default key type.
    /// Performance-optimized for generating more than 1 key
    ///
    /// - Parameter numberOfKeyPairs: Number of keys needed
    /// - Returns: Array of generated keys
    /// - Throws: Rethrows from KeyPair
    @objc open func generateMultipleKeyPairs(numberOfKeyPairs: UInt) throws -> [VirgilKeyPair] {
        return try KeyPair
            .generateMultipleKeys(numberOfKeyPairs, keyPairType: self.defaultKeyType)
            .map({ try self.wrapKeyPair(keyPair: $0) })
    }

    /// Generates KeyPair of default key type
    ///
    /// NOTE: If you need more than 1 keypair, consider using generateMultipleKeyPairs
    ///
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyPair
    @objc open func generateKeyPair() throws -> VirgilKeyPair {
        return try self.generateKeyPair(ofType: self.defaultKeyType)
    }

    /// Generates KeyPair of given type
    ///
    /// NOTE: If you need more than 1 keypair, consider using generateMultipleKeyPairs
    ///
    /// - Parameter type: KeyPair type
    /// - Returns: Generated KeyPair
    /// - Throws: Rethrows from KeyPair
    @objc open func generateKeyPair(ofType type: VSCKeyType) throws -> VirgilKeyPair {
        let keyPair = KeyPair(keyPairType: type, password: nil)

        return try self.wrapKeyPair(keyPair: keyPair)
    }

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
}
