//
//  VirgilCrypto.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/18/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

@objc(VSCVirgilCrypto) public class VirgilCrypto: NSObject, Crypto {
    /// Exports public key to its raw data representation.
    ///
    /// - Parameter publicKey: public key to be exported
    /// - Returns: raw public key representation
    /// - Throws: corresponding error
    public func exportPublicKey(_ publicKey: PublicKey) throws -> Data {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw NSError()
        }
        
        return publicKey.key
    }

    /// Imports public key from its raw data representation.
    ///
    /// - Parameter data: raw public key representation
    /// - Returns: imported public key
    /// - Throws: corresponding error
    public func importPublicKey(from data: Data) throws -> PublicKey {
        guard let publicKeyDER = VSCKeyPair.publicKey(toDER: data) else {
            throw NSError()
        }
        
        let hash = VSCHash(algorithm: .SHA256)!
        
        let identifier = hash.hash(publicKeyDER)!
        
        return VirgilPublicKey(identifier: identifier, key: publicKeyDER)
    }

    /// Computes SHA-256.
    ///
    /// - Parameter data: the data to be hashed
    /// - Returns: the resulting hash value
    public func computeSHA256(for data: Data) -> Data {
        let hash = VSCHash(algorithm: .SHA256)!
        
        return hash.hash(data)!
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
        
        let signer = VSCSigner()
        
        try signer.verifySignature(signature, data: data, publicKey: publicKey.key)
    }

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
        
        let signer = VSCSigner()
        
        return try signer.sign(data, privateKey: privateKey.key, keyPassword: nil)
    }
    
}
