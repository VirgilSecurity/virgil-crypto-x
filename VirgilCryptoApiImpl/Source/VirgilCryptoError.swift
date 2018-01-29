//
//  VirgilCryptoError.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/17/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

@objc(VSMVirgilCryptoError) public enum VirgilCryptoError: Int, Error {
    case passedKeyIsNotVirgil
    case signerNotFound
    case extractPublicKeyFailed
    case encryptPrivateKeyFailed
    case decryptPrivateKeyFailed
    case privateKeyToDERFailed
    case publicKeyToDERFailed
}
