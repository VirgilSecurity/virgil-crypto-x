//
//  VirgilCrypto+KeyManagement.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

extension VirgilCrypto {
    @objc open func computeKeyIdentifier(publicKeyData: Data) -> Data {
        if self.useSHA256Fingerprints {
            return self.computeHash(for: publicKeyData, using: .SHA256)
        }
        else {
            return self.computeHash(for: publicKeyData, using: .SHA512).subdata(in: 0..<8)
        }
    }

    @objc open func importPrivateKey(from data: Data, password: String? = nil) throws -> VirgilPrivateKey {
        let privateKeyData: Data
        if let password = password {
            guard let decryptedPrivateKeyData = KeyPair.decryptPrivateKey(data, privateKeyPassword: password) else {
                throw VirgilCryptoError.decryptPrivateKeyFailed
            }

            privateKeyData = decryptedPrivateKeyData
        }
        else {
            privateKeyData = data
        }

        guard let privateKeyDER = KeyPair.privateKey(toDER: privateKeyData) else {
            throw VirgilCryptoError.privateKeyToDERFailed
        }

        guard let publicKeyData = KeyPair.extractPublicKey(fromPrivateKey: privateKeyDER,
                                                           privateKeyPassword: nil) else {
            throw VirgilCryptoError.extractPublicKeyFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPrivateKey(identifier: identifier, rawKey: privateKeyDER)
    }

    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey) -> Data {
        return privateKey.rawKey
    }

    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey, password: String) throws -> Data {
        guard let encryptedPrivateKeyData = KeyPair.encryptPrivateKey(privateKey.rawKey,
                                                                      privateKeyPassword: password) else {
            throw VirgilCryptoError.encryptPrivateKeyFailed
        }

        return encryptedPrivateKeyData
    }

    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        guard let publicKeyData = KeyPair.extractPublicKey(fromPrivateKey: privateKey.rawKey,
                                                           privateKeyPassword: nil) else {
            throw VirgilCryptoError.extractPublicKeyFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPublicKey(identifier: identifier, rawKey: publicKeyData)
    }

    @objc open func exportPublicKey(_ publicKey: VirgilPublicKey) -> Data {
        return publicKey.rawKey
    }

    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        guard let publicKeyData = KeyPair.publicKey(toDER: data) else {
            throw VirgilCryptoError.publicKeyToDERFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPublicKey(identifier: identifier, rawKey: publicKeyData)
    }
}
