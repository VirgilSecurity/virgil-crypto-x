//
//  VirgilKeyPair.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSMVirgilKeyPair) public class VirgilKeyPair: NSObject {
    @objc public let privateKey: VirgilPrivateKey
    @objc public let publicKey: VirgilPublicKey
    
    @objc public init(privateKey: VirgilPrivateKey, publicKey: VirgilPublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        
        super.init()
    }
}
