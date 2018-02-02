//
//  VSP001_PFSTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 6/14/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
import XCTest

class VSP001_PFSTests: XCTestCase {
    private func generateSessions(additionalDataPresent: Bool, oneTimePresent: Bool) -> (Pfs, PfsSession, Pfs, PfsSession) {
        let initiatorIdentityKeyPair = KeyPair()
        let initiatorEphemeralKeyPair = KeyPair()
        let initiatorIdentityPrivateKey = PfsPrivateKey(key: initiatorIdentityKeyPair.privateKey(), password: nil)!
        let initiatorIdentityPublicKey = PfsPublicKey(key: initiatorIdentityKeyPair.publicKey())!
        let initiatorEphemeralPrivateKey = PfsPrivateKey(key: initiatorEphemeralKeyPair.privateKey(), password: nil)!
        let initiatorEphemeralPublicKey = PfsPublicKey(key: initiatorEphemeralKeyPair.publicKey())!
        let initiatorAdditionalData = additionalDataPresent ? "Alice+Bob".data(using: .utf8) : nil
        
        let responderIdentityKeyPair = KeyPair()
        let responderLongTermKeyPair = KeyPair()
        let responderOneTimeKeyPair = KeyPair()
        let responderIdentityPublicKey = PfsPublicKey(key: responderIdentityKeyPair.publicKey())!
        let responderIdentityPrivateKey = PfsPrivateKey(key: responderIdentityKeyPair.privateKey(), password: nil)!
        let responderLongTermPublicKey = PfsPublicKey(key: responderLongTermKeyPair.publicKey())!
        let responderLongTermPrivateKey = PfsPrivateKey(key: responderLongTermKeyPair.privateKey(), password: nil)!
        let responderAdditionalData = additionalDataPresent ? "Alice+Bob".data(using: .utf8) : nil
        
        let responderOneTimePublicKey = oneTimePresent ? PfsPublicKey(key: responderOneTimeKeyPair.publicKey())! : nil
        let responderOneTimePrivateKey = oneTimePresent ? PfsPrivateKey(key: responderOneTimeKeyPair.privateKey(), password: nil)! : nil
        
        let initiatorPrivateInfo = PfsInitiatorPrivateInfo(identityPrivateKey: initiatorIdentityPrivateKey, ephemeralPrivateKey: initiatorEphemeralPrivateKey)!
        let responderPublicInfo = PfsResponderPublicInfo(identityPublicKey: responderIdentityPublicKey, longTermPublicKey: responderLongTermPublicKey, oneTime: responderOneTimePublicKey)!
        
        let initiatorPfs = Pfs()
        let initiatorSession = initiatorPfs.startInitiatorSession(with: initiatorPrivateInfo, respondrerPublicInfo: responderPublicInfo, additionalData: initiatorAdditionalData)!
        
        let initiatorPublicInfo = PfsInitiatorPublicInfo(identityPublicKey: initiatorIdentityPublicKey, ephemeralPublicKey: initiatorEphemeralPublicKey)!
        let responderPrivateInfo = PfsResponderPrivateInfo(identityPrivateKey: responderIdentityPrivateKey, longTermPrivateKey: responderLongTermPrivateKey, oneTime: responderOneTimePrivateKey)!
        
        let responderPfs = Pfs()
        let responderSession = responderPfs.startResponderSession(with: responderPrivateInfo, initiatorPublicInfo: initiatorPublicInfo, additionalData: responderAdditionalData)!
        
        return (initiatorPfs, initiatorSession, responderPfs, responderSession)
    }
    
    func test001_encryptDecrypt_oneTimePresent() {
        let (initiatorPfs, _, responderPfs, _) = self.generateSessions(additionalDataPresent: false, oneTimePresent: true)
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
    
    func test002_encryptDecrypt_oneTimeAbsent() {
        let (initiatorPfs, _, responderPfs, _) = self.generateSessions(additionalDataPresent: false, oneTimePresent: false)
        
        let data = "Hello, Bob!".data(using: .utf8)!
        
        let encryptedData = initiatorPfs.encryptData(data)!
        
        let decryptedData = responderPfs.decryptMessage(encryptedData)!
        
        XCTAssert(data == decryptedData)
    }
    
    func test003_validateSessionData_addionalDataAbsent() {
        let (_, initiatorSession, _, responderSession) = self.generateSessions(additionalDataPresent: false, oneTimePresent: true)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
        
        XCTAssert(initiatorSession.additionalData.count != 0)
        XCTAssert(initiatorSession.decryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.encryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.identifier.count != 0)
        
        XCTAssert(responderSession.additionalData.count != 0)
        XCTAssert(responderSession.decryptionSecretKey.count != 0)
        XCTAssert(responderSession.encryptionSecretKey.count != 0)
        XCTAssert(responderSession.identifier.count != 0)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
    }
    
    func test004_validateSessionData_addionalDataPresent() {
        let (_, initiatorSession, _, responderSession) = self.generateSessions(additionalDataPresent: true, oneTimePresent: true)
        XCTAssert(initiatorSession.additionalData.count != 0)
        XCTAssert(initiatorSession.decryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.encryptionSecretKey.count != 0)
        XCTAssert(initiatorSession.identifier.count != 0)
        
        XCTAssert(responderSession.additionalData.count != 0)
        XCTAssert(responderSession.decryptionSecretKey.count != 0)
        XCTAssert(responderSession.encryptionSecretKey.count != 0)
        XCTAssert(responderSession.identifier.count != 0)
        
        XCTAssert(initiatorSession.identifier == responderSession.identifier);
    }
}
