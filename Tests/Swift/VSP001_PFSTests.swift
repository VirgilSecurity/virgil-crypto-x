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
    private func generateSessions() -> (VSCPfs, VSCPfsSession, VSCPfs, VSCPfsSession) {
        let initiatorIdentityKeyPair = VSCKeyPair()
        let initiatorEphemeralKeyPair = VSCKeyPair()
        let initiatorIdentityPrivateKey = VSCPfsPrivateKey(key: initiatorIdentityKeyPair.privateKey(), password: nil)!
        let initiatorIdentityPublicKey = VSCPfsPublicKey(key: initiatorIdentityKeyPair.publicKey())!
        let initiatorEphemeralPrivateKey = VSCPfsPrivateKey(key: initiatorEphemeralKeyPair.privateKey(), password: nil)!
        let initiatorEphemeralPublicKey = VSCPfsPublicKey(key: initiatorEphemeralKeyPair.publicKey())!
        
        let responderIdentityKeyPair = VSCKeyPair()
        let responderLongTermKeyPair = VSCKeyPair()
        let responderOneTimeKeyPair = VSCKeyPair()
        let responderIdentityPublicKey = VSCPfsPublicKey(key: responderIdentityKeyPair.publicKey())!
        let responderIdentityPrivateKey = VSCPfsPrivateKey(key: responderIdentityKeyPair.privateKey(), password: nil)!
        let responderLongTermPublicKey = VSCPfsPublicKey(key: responderLongTermKeyPair.publicKey())!
        let responderLongTermPrivateKey = VSCPfsPrivateKey(key: responderLongTermKeyPair.privateKey(), password: nil)!
        let responderOneTimePublicKey = VSCPfsPublicKey(key: responderOneTimeKeyPair.publicKey())!
        let responderOneTimePrivateKey = VSCPfsPrivateKey(key: responderOneTimeKeyPair.privateKey(), password: nil)!
        
        let initiatorPrivateInfo = VSCPfsInitiatorPrivateInfo(identityPrivateKey: initiatorIdentityPrivateKey, ephemeralPrivateKey: initiatorEphemeralPrivateKey)!
        let responderPublicInfo = VSCPfsResponderPublicInfo(identityPublicKey: responderIdentityPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey)!
        
        let initiatorPfs = VSCPfs()
        let initiatorSession = initiatorPfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo)!
        
        let initiatorPublicInfo = VSCPfsInitiatorPublicInfo(identityPublicKey: initiatorIdentityPublicKey, ephemeralPublicKey: initiatorEphemeralPublicKey)!
        let responderPrivateInfo = VSCPfsResponderPrivateInfo(identityPrivateKey: responderIdentityPrivateKey, longTermPrivateKey: responderLongTermPrivateKey, oneTime: responderOneTimePrivateKey)!
        
        let responderPfs = VSCPfs()
        let responderSession = responderPfs.startResponderSession(with: responderPrivateInfo, respondrerPublicInfo: initiatorPublicInfo)!
        
        return (initiatorPfs, initiatorSession, responderPfs, responderSession)
    }
    
    func test001_encryptDecrypt() {
        let (initiatorPfs, _, responderPfs, _) = self.generateSessions()
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
    
    func test002_validateSessionData() {
        let (_, initiatorSession, _, responderSession) = self.generateSessions()
//        XCTAssert(initiatorSession.additionalData.count != 0)
        XCTAssert(initiatorSession.decryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.encryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.identifier.count != 0)
        XCTAssert(!initiatorSession.isEmpty)
        
//        XCTAssert(responderSession.additionalData.count != 0)
        XCTAssert(responderSession.decryptionSecretKey.count != 0)
        XCTAssert(responderSession.encryptionSecretKey.count != 0)
        XCTAssert(responderSession.identifier.count != 0)
        XCTAssert(!responderSession.isEmpty)
    }
}
