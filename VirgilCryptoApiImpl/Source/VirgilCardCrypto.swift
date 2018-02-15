//
//  VirgilCardCrypto.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/4/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

/// Adapter for CardCrypto protocol using VirgilCrypto
@objc(VSMVirgilCardCrypto) public class VirgilCardCrypto: NSObject {
    /// VirgilCrypto instance
    @objc public let virgilCrypto: VirgilCrypto

    /// Initializer
    ///
    /// - Parameter virgilCrypto: VirgilCrypto instance
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto()) {
        self.virgilCrypto = virgilCrypto

        super.init()
    }
}

// MARK: - Implementation of CardCrypto protocol
extension VirgilCardCrypto: CardCrypto {
    /// Generates digital signature of data using specified private key.
    ///
    /// - Parameters:
    ///   - data: Data to be signed
    ///   - privateKey: Signer's private key
    /// - Returns: Digitar signature data
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func generateSignature(of data: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return try self.virgilCrypto.generateSignature(of: data, using: privateKey)
    }

    /// Verifies digital signature.
    ///
    /// - Parameters:
    ///   - signature: Digital signature data
    ///   - data: Data that was signed
    ///   - publicKey: Signer's public key
    /// - Returns: true if verified, false otherwise
    public func verifySignature(_ signature: Data, of data: Data, with publicKey: PublicKey) -> Bool {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            return false
        }

        return self.virgilCrypto.verifySignature(signature, of: data, with: publicKey)
    }

    /// Computes SHA-512.
    ///
    /// - Parameter data: Data to be hashed
    /// - Returns: Resulting hash value
    /// - Throws: Doesn't throw. throws added to conform to protocol
    public func generateSHA512(for data: Data) throws -> Data {
         return self.virgilCrypto.computeHash(for: data, using: .SHA512)
    }

    /// Imports public key from DER or PEM format
    ///
    /// - Parameter data: Public key data in DER or PEM format
    /// - Returns: Imported public key
    /// - Throws: Rethrows from VirgilCrypto
    public func importPublicKey(from data: Data) throws -> PublicKey {
        return try self.virgilCrypto.importPublicKey(from: data)
    }

    /// Exports public key to DER format
    ///
    /// - Parameter publicKey: Public key to be exported
    /// - Returns: Public key in DER format
    /// - Throws: VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func exportPublicKey(_ publicKey: PublicKey) throws -> Data {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return self.virgilCrypto.exportPublicKey(publicKey)
    }
}
