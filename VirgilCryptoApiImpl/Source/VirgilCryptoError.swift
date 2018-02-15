//
//  VirgilCryptoError.swift
//  VirgilCrypto
//
//  Created by Eugen Pivovarov on 1/17/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation

/// Declares error types and codes
///
/// - passedKeyIsNotVirgil: passed key type is incorrect
/// - signerNotFound: signer with this id is not found
/// - extractPublicKeyFailed: public key extraction failed
/// - encryptPrivateKeyFailed: private key encryption failed
/// - decryptPrivateKeyFailed: private key decryption failed
/// - privateKeyToDERFailed: conversion of private key to DER failed
/// - publicKeyToDERFailed: conversion of public key to DER failed
@objc(VSMVirgilCryptoError) public enum VirgilCryptoError: Int, Error {
    case passedKeyIsNotVirgil = 1
    case signerNotFound = 2
    case extractPublicKeyFailed = 3
    case encryptPrivateKeyFailed = 4
    case decryptPrivateKeyFailed = 5
    case privateKeyToDERFailed = 6
    case publicKeyToDERFailed = 7
}
