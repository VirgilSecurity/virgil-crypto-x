//
//  VirgilCrypto+KeyManagement.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto

// MARK: - Extension for key management
extension VirgilCrypto {
    /// Computes key identifiers
    ///
    /// NOTE: Takes first 8 bytes of SHA512 of public key DER if useSHA256Fingerprints=false
    ///       and SHA256 of public key der if useSHA256Fingerprints=true
    ///
    /// - Parameter publicKeyData: Public key data
    /// - Returns: Public key identifier
    @objc open func computeKeyIdentifier(publicKeyData: Data) -> Data {
        if self.useSHA256Fingerprints {
            return self.computeHash(for: publicKeyData, using: .SHA256)
        }
        else {
            return self.computeHash(for: publicKeyData, using: .SHA512).subdata(in: 0..<8)
        }
    }

    /// Imports private key from raw data in DER or PEM format
    ///
    /// - Parameters:
    ///   - data: Private key in DER or PEM format
    ///   - password: Password, if password is encrypted
    /// - Returns: Import PrivateKey
    /// - Throws: VirgilCryptoError.decryptPrivateKeyFailed, if private key descryption failed
    ///           VirgilCryptoError.privateKeyToDERFailed, if private key is corrupted, and conversion to DER failed
    ///           VirgilCryptoError.extractPublicKeyFailed, if public key extraction failed
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

    /// Exports private key to DER foramt
    ///
    /// WARNING: Consider using export with password
    ///
    /// - Parameter privateKey: Private key to export
    /// - Returns: Private key in DER format
    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey) -> Data {
        return privateKey.rawKey
    }

    /// Expots encrypted using password private key
    ///
    /// - Parameters:
    ///   - privateKey: PrivateKey to export
    ///   - password: Password
    /// - Returns: Exported encrypted private key
    /// - Throws: VirgilCryptoError.encryptPrivateKeyFailed, if encryption failed
    @objc open func exportPrivateKey(_ privateKey: VirgilPrivateKey, password: String) throws -> Data {
        guard let encryptedPrivateKeyData = KeyPair.encryptPrivateKey(privateKey.rawKey,
                                                                      privateKeyPassword: password) else {
            throw VirgilCryptoError.encryptPrivateKeyFailed
        }

        return encryptedPrivateKeyData
    }

    /// Extracts public key from private key
    ///
    /// - Parameter privateKey: Private key
    /// - Returns: Public Key that matches passed Private Key
    /// - Throws: VirgilCryptoError.extractPublicKeyFailed, if extraction failed
    @objc open func extractPublicKey(from privateKey: VirgilPrivateKey) throws -> VirgilPublicKey {
        guard let publicKeyData = KeyPair.extractPublicKey(fromPrivateKey: privateKey.rawKey,
                                                           privateKeyPassword: nil) else {
            throw VirgilCryptoError.extractPublicKeyFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPublicKey(identifier: identifier, rawKey: publicKeyData)
    }

    /// Exports public key in DER format
    ///
    /// - Parameter publicKey: PublicKey to export
    /// - Returns: Exported public key in DER format
    @objc open func exportPublicKey(_ publicKey: VirgilPublicKey) -> Data {
        return publicKey.rawKey
    }

    /// Import public key from DER or PEM format
    ///
    /// - Parameter data: Public key in DER or PEM format
    /// - Returns: Imported Public Key
    /// - Throws: VirgilCryptoError.publicKeyToDERFailed, if public key is corrupted and conversion to DER failed
    @objc open func importPublicKey(from data: Data) throws -> VirgilPublicKey {
        guard let publicKeyData = KeyPair.publicKey(toDER: data) else {
            throw VirgilCryptoError.publicKeyToDERFailed
        }

        let identifier = self.computeKeyIdentifier(publicKeyData: publicKeyData)

        return VirgilPublicKey(identifier: identifier, rawKey: publicKeyData)
    }
}
