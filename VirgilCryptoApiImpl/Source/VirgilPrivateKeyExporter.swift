//
//  VirgilPrivateKeyExporter.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/15/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

import VirgilCryptoAPI

@objc(VSMVirgilPrivateKeyExporter) public class VirgilPrivateKeyExporter: NSObject {
    private let virgilCrypto: VirgilCrypto
    private let password: String?
    
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto(defaultKeyType: .FAST_EC_ED25519), password: String? = nil) {
        self.virgilCrypto = virgilCrypto
        self.password = password
    }
}

// MARK: - Implementation of PrivateKeyExporter protocol
extension VirgilPrivateKeyExporter: PrivateKeyExporter {
    /// Exports data of specified Private key.
    ///
    /// - Parameters:
    ///   - privateKey: the private key to be exported
    /// - Returns: exported private key data
    /// - Throws: correspoding error
    public func exportPrivateKey(privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }
        
        return try self.virgilCrypto.exportPrivateKey(privateKey, password: self.password)
    }
    
    /// Imports Private Key from data
    ///
    /// - Parameters:
    ///   - data: the data to be imported
    /// - Returns: imported Private Key instance
    /// - Throws: error if verification failed
    public func importPrivateKey(from data: Data) throws -> PrivateKey {
        return try self.virgilCrypto.importPrivateKey(from: data)
    }
}
