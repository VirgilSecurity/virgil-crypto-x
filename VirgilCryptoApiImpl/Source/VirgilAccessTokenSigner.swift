//
//  VirgilAccessTokenSigner.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/5/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

/// Adapter for AccessTokenSigner implementation using VirgilCrypto
@objc(VSMVirgilAccessTokenSigner) public class VirgilAccessTokenSigner: NSObject {
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
        
        return try self.virgilCrypto.generateSignature(of: token, using: privateKey)
    }
    
    /// Verifies the passed-in token's signature.
    ///
    /// - Parameters:
    ///   - signature: the signature bytes to be verified
    ///   - token: the token to be verified
    ///   - publicKey: the public key of the identity whose signature is going to be verified
    /// - Returns: true if verified, false otherwise
    public func verifyTokenSignature(_ signature: Data, of token: Data, with publicKey: PublicKey) -> Bool {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            return false
        }
        
        return self.virgilCrypto.verifySignature(signature, of: token, with: publicKey)
    }
    
    ///Represets algorithm used for signing
    ///
    /// - Returns: algorithm title as String
    public func getAlgorithm() -> String {
        return "VEDS512"
    }    
}

