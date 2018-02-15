//
//  VirgilPrivateKey.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/18/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

/// Represents PrivateKey for operations with VirgilCrypto class
@objc(VSMVirgilPrivateKey) public final class VirgilPrivateKey: NSObject {
    /// Private key identifier.
    /// Equals to first 8 bytes of SHA-512 of public key in DER foramt
    @objc public let identifier: Data
    internal let rawKey: Data

    internal init(identifier: Data, rawKey: Data) {
        self.identifier = identifier
        self.rawKey = rawKey

        super.init()
    }
}

// MARK: - Adding implementation of PrivateKey marker protocol
extension VirgilPrivateKey: PrivateKey { }
