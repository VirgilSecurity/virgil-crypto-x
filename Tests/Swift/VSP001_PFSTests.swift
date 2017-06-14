//
//  VSP001_PFSTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation

import XCTest

class VSP001_PFSTests: XCTestCase {
    func test001_encryptDecrypt() {
        let initiatorIdentityKeyPair = VSCKeyPair()
        let initiatorEphemeralKeyPair = VSCKeyPair()
        let initiatorIdentityPrivateKey = VSCPfsPrivateKey(key: initiatorIdentityKeyPair.privateKey(), password: nil)!
        let initiatorIdentityPublicKey = VSCPfsPublicKey(key: initiatorIdentityKeyPair.publicKey())!
        let initiatorEphemeralPrivateKey = VSCPfsPrivateKey(key: initiatorEphemeralKeyPair.privateKey(), password: nil)!
        let initiatorEphemeralPublicKey = VSCPfsPublicKey(key: initiatorEphemeralKeyPair.publicKey())!
        let initiatorIdentifier = "Alice"
        
        let responderIdentifier = "Bob"
        let responderIdentityKeyPair = VSCKeyPair()
        let responderLongTermKeyPair = VSCKeyPair()
        let responderOneTimeKeyPair = VSCKeyPair()
        let responderIdentityPublicKey = VSCPfsPublicKey(key: responderIdentityKeyPair.publicKey())!
        let responderIdentityPrivateKey = VSCPfsPrivateKey(key: responderIdentityKeyPair.privateKey(), password: nil)!
        let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermKeyPair.publicKey())!
        let responderLongTermPrivateKey = VSCPfsPrivateKey(key: responderLongTermKeyPair.privateKey(), password: nil)!
        let responderOneTimePublicKey = VSCPfsPublicKey(key: responderOneTimeKeyPair.publicKey())!
        let responderOneTimePrivateKey = VSCPfsPrivateKey(key: responderOneTimeKeyPair.privateKey(), password: nil)!
        
        let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identifier: initiatorIdentifier, identityPrivateKey: initiatorIdentityPrivateKey, ephemeralPrivateKey: initiatorEphemeralPrivateKey)!
        let responderPublicInfo = VSCPfsResponderPublicInfo(identifier: responderIdentifier, identityPublicKey: responderIdentityPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey)!
        
        let initiatorPfs = VSCPfs()
        let _ = initiatorPfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo)
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let initiatorPublicInfo = VSCPfsInitiatorPublicInfo(identifier: initiatorIdentifier, identityPublicKey: initiatorIdentityPublicKey, ephemeralPublicKey: initiatorEphemeralPublicKey)!
        let responderPrivateInfo = VSCPfsResponderPrivateInfo(identifier: responderIdentifier, identityPrivateKey: responderIdentityPrivateKey, longTermPrivateKey: responderLongTermPrivateKey, oneTime: responderOneTimePrivateKey)!
        
        let responderPfs = VSCPfs()
        let _ = responderPfs.startResponderSession(with: responderPrivateInfo, respondrerPublicInfo: initiatorPublicInfo)
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
}
