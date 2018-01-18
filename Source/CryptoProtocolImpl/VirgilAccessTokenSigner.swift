//
//  VirgilAccessTokenSigner.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/5/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

@objc(VSAVirgilAccessTokenSigner) public class VirgilAccessTokenSigner: NSObject {
    let virgilCrypto = VirgilCrypto(defaultKeyType: .FAST_EC_ED25519)
}

// MARK: - Implementation of AccessTokenSigner protocol
extension VirgilAccessTokenSigner: AccessTokenSigner {
    /// Generates the digital signature of data using specified private key.
    ///
    /// - Parameters:
    ///   - token: the token to be signed
    ///   - privateKey: the private key of the identity whose signature is going to be generated
    /// - Returns: signature data
    /// - Throws: correspoding error
    public func generateTokenSignature(of token: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }
        
        return try self.virgilCrypto.generateSignature(of: token, usingVirgil: privateKey)
    }
    
    /// Verifies the passed-in token's signature.
    ///
    /// - Parameters:
    ///   - signature: the signature bytes to be verified
    ///   - token: the token to be verified
    ///   - publicKey: the public key of the identity whose signature is going to be verified
    /// - Throws: error if verification failed
    public func verifyTokenSignature(_ signature: Data, of token: Data, with publicKey: PublicKey) throws {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }
        
        try self.virgilCrypto.verifySignature(signature, of: token, with: publicKey)
    }
    
    ///Represets algorithm used for signing
    ///
    /// - Returns: algorithm title as String
    public func getAlgorithm() -> String {
        return "VEDS512"
    }    
}

