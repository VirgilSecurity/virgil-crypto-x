//
//  VirgilPublicKey.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/18/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

@objc(VSMVirgilPublicKey) public final class VirgilPublicKey: NSObject {
    @objc public let identifier: Data
    internal let rawKey: Data

    internal init(identifier: Data, rawKey: Data) {
        self.identifier = identifier
        self.rawKey = rawKey

        super.init()
    }
}

extension VirgilPublicKey: PublicKey { }
