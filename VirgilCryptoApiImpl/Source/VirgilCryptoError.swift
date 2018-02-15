//
//  VirgilCryptoError.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/17/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSMVirgilCryptoError) public enum VirgilCryptoError: Int, Error {
    case passedKeyIsNotVirgil = 1
    case signerNotFound = 2
    case extractPublicKeyFailed = 3
    case encryptPrivateKeyFailed = 4
    case decryptPrivateKeyFailed = 5
    case privateKeyToDERFailed = 6
    case publicKeyToDERFailed = 7
}
