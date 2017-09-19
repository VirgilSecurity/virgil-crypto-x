//
//  VirgilKeyPair.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/19/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSSVirgilKeyPair) public class VirgilKeyPair: NSObject {
    public let privateKey: VirgilPrivateKey
    public let publicKey: VirgilPublicKey
    
    public init(privateKey: VirgilPrivateKey, publicKey: VirgilPublicKey) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        
        super.init()
    }
}
