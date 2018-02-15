//
//  VirgilKeyPair.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

/// Aggregates Private and Public key.
@objc(VSMVirgilKeyPair) public final class VirgilKeyPair: NSObject {
    /// Private key
    @objc public let privateKey: VirgilPrivateKey
    /// Public key
    @objc public let publicKey: VirgilPublicKey

    /// Initializer
    ///
    /// - Parameters:
    ///   - privateKey: Private key
    ///   - publicKey: Public key
    @objc public init(privateKey: VirgilPrivateKey, publicKey: VirgilPublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey

        super.init()
    }
}
