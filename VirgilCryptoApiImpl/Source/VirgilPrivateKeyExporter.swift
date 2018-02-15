//
//  VirgilPrivateKeyExporter.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/15/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

import VirgilCryptoAPI

/// Adapter for PrivateKeyExporter protocol using VirgilCrypto
@objc(VSMVirgilPrivateKeyExporter) open class VirgilPrivateKeyExporter: NSObject {
    /// VirgilCrypto instance
    @objc public let virgilCrypto: VirgilCrypto
    /// Password used to encrypt private key. Do NOT use nil, unless your storage/transport channel is secured
    @objc public let password: String?

    /// Initializer
    ///
    /// - Parameters:
    ///   - virgilCrypto: VirgilCrypto instance
    ///   - password: Password used to encrypt private key.
    ///               NOTE: Do NOT use nil, unless your storage/transport channel is secured
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto(), password: String? = nil) {
        self.virgilCrypto = virgilCrypto
        self.password = password

        super.init()
    }
}

// MARK: - Implementation of PrivateKeyExporter protocol
extension VirgilPrivateKeyExporter: PrivateKeyExporter {
    /// Exports private key to DER format
    ///
    /// - Parameters:
    ///   - privateKey: Private key to be exported
    /// - Returns: Exported private key in DER format
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    @objc open func exportPrivateKey(privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        if let password = self.password {
            return try self.virgilCrypto.exportPrivateKey(privateKey, password: password)
        }
        else {
            return self.virgilCrypto.exportPrivateKey(privateKey)
        }
    }

    /// Imports Private Key from DER or PEM format
    ///
    /// - Parameter data: Private key in DER or PEM format
    /// - Returns: Imported private key
    /// - Throws: Rethrows from VirgilCrypto
    @objc open func importPrivateKey(from data: Data) throws -> PrivateKey {
        return try self.virgilCrypto.importPrivateKey(from: data)
    }
}
