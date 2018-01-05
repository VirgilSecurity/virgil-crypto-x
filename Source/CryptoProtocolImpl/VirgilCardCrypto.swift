//
//  VirgilCardCrypto.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/4/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

@objc(VSCVirgilCardCrypto) public class VirgilCardCrypto: NSObject {
    let virgilCrypto = VirgilCrypto()
}

// MARK: - Implementation of CardCrypto protocol
extension VirgilCardCrypto : CardCrypto {
    /// Generates the digital signature of data using specified private key.
    ///
    /// - Parameters:
    ///   - data: the data to be signed
    ///   - privateKey: the private key of the identity whose signature is going to be generated
    /// - Returns: signature data
    public func generateSignature(of data: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw NSError()
        }
        
        return try self.virgilCrypto.generateSignature(of: data, usingVirgil: privateKey)
    }
    
    /// Verifies the passed-in signature.
    ///
    /// - Parameters:
    ///   - signature: the signature bytes to be verified
    ///   - data: the data to be verified
    ///   - publicKey: the public key of the identity whose signature is going to be verified
    /// - Throws: error if verification failed
    public func verifySignature(_ signature: Data, of data: Data, with publicKey: PublicKey) throws {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        try self.virgilCrypto.verifySignature(signature, of: data, withVirgil: publicKey)
    }
    
    /// Computes SHA-256.
    ///
    /// - Parameter data: the data to be hashed
    /// - Returns: the resulting hash value
    public func computeSHA256(for data: Data) -> Data {
         return self.virgilCrypto.computeHash(for: data, using: .SHA256)
    }
    
    /// Imports public key from its raw data representation.
    ///
    /// - Parameter data: raw public key representation
    /// - Returns: imported public key
    /// - Throws: corresponding error
    public func importPublicKey(from data: Data) throws -> PublicKey {
        return try self.virgilCrypto.importVirgilPublicKey(from: data)
    }
    
    /// Exports public key to its raw data representation.
    ///
    /// - Parameter publicKey: public key to be exported
    /// - Returns: raw public key representation
    /// - Throws: corresponding error
    public func exportPublicKey(_ publicKey: PublicKey) throws -> Data {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        return try self.virgilCrypto.exportVirgilPublicKey(publicKey)
    }
}
