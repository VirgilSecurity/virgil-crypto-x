//
//  VirgilPrivateKeyExporter.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/15/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

import VirgilCryptoAPI

@objc(VSAVirgilPrivateKeyExporter) public class VirgilPrivateKeyExporter: NSObject {
    private let virgilCrypto: VirgilCrypto
    private let password: String?
    
    @objc public init(virgilCrypto: VirgilCrypto = VirgilCrypto(defaultKeyType: .FAST_EC_ED25519), password: String? = nil) {
        self.virgilCrypto = virgilCrypto
        self.password = password
    }
}

extension VirgilPrivateKeyExporter: PrivateKeyExporter {
    public func exportPrivateKey(privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw NSError()
        }
        
        return try self.virgilCrypto.exportPrivateKey(privateKey, password: self.password)
    }
    
    public func importPrivateKey(data: Data) throws -> PrivateKey {
        return try self.virgilCrypto.importPrivateKey(fromData: data)
    }
}
