//
//  VirgilAccessTokenSigner.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/5/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

/// Adapter for AccessTokenSigner protocol using VirgilCrypto
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
    /// Generates digital signature for token
    ///
    /// - Parameters:
    ///   - token: Token to be signed
    ///   - privateKey: Private key
    /// - Returns: Digital signature data
    /// - Throws: Rethrows from VirgilCrypto.
    ///           VirgilCryptoError.passedKeyIsNotVirgil if passed key is of wrong type
    public func generateTokenSignature(of token: Data, using privateKey: PrivateKey) throws -> Data {
        guard let privateKey = privateKey as? VirgilPrivateKey else {
            throw VirgilCryptoError.passedKeyIsNotVirgil
        }

        return try self.virgilCrypto.generateSignature(of: token, using: privateKey)
    }

    /// Verifies token's signature.
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - token: Token data
    ///   - publicKey: Signer's public key
    /// - Returns: true if verified, false otherwise
    public func verifyTokenSignature(_ signature: Data, of token: Data, with publicKey: PublicKey) -> Bool {
        guard let publicKey = publicKey as? VirgilPublicKey else {
            return false
        }

        return self.virgilCrypto.verifySignature(signature, of: token, with: publicKey)
    }

    /// Returns algorithm used for signing
    ///
    /// - Returns: algorithm string. Currently VEDS512
    public func getAlgorithm() -> String {
        return "VEDS512"
    }
}
