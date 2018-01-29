//
//  VSC001_KeyPairTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC001_KeyPairTests: XCTestCase {
    func test001_createKeyPair() {
        let keyPair = VSCKeyPair()
        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should have actual content.");
        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should have actual content.");
        
        if let keyString = NSString(data: keyPair.privateKey(), encoding: String.Encoding.utf8.rawValue) {
            let range = keyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive])
            XCTAssertTrue(range.length == 0, "Private key should be generated in plain form.");
        }
    }
    
    func test002_createKeyPairWithPassword() {
        let password = "secret"
        let keyPair = VSCKeyPair(keyPairType: .RSA_512, password: password)
        XCTAssert(keyPair.publicKey().count > 0)
        XCTAssert(keyPair.privateKey().count > 0)
        
        let privateKeyString = String(data: keyPair.privateKey(), encoding: .utf8)!
        
        XCTAssert(privateKeyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive]) != nil)
        
        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should be generated for the new key pair.");
        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should be generated for the new key pair.");
    }
    
    func test003_encryptDecryptPrivateKeyWithPassword() {
        let keyPair = VSCKeyPair()
        let password = "secret"
        
        let encryptedPrivateKey = VSCKeyPair.encryptPrivateKey(keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(encryptedPrivateKey.count > 0)
        
        let decryptedPrivateKey = VSCKeyPair.decryptPrivateKey(encryptedPrivateKey, privateKeyPassword: password)!
        
        XCTAssert(decryptedPrivateKey.count > 0)
        
        XCTAssert(decryptedPrivateKey == keyPair.privateKey())
    }
    
    func test004_extractPublicKeyWithPassword() {
        let password = "secret"
        let keyPair = VSCKeyPair(keyPairType: .RSA_512, password: password)
        
        let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(publicKeyData.count > 0)
    }
    
    func test005_extractPublicKeyWithoutPassword() {
        let keyPair = VSCKeyPair(keyPairType: .RSA_512, password: nil)
        
        let publicKeyData = VSCKeyPair.extractPublicKey(withPrivateKey: keyPair.privateKey(), privateKeyPassword: nil)!
        XCTAssert(publicKeyData.count > 0)
    }

    func test006_extractPublicKeysToPemAndDer() {
        let keyPair = VSCKeyPair()
        
        let pemData = VSCKeyPair.publicKey(toPEM: keyPair.publicKey())!
        XCTAssert(pemData.count > 0)
        let derData = VSCKeyPair.publicKey(toDER: keyPair.publicKey())!
        XCTAssert(derData.count > 0)
    }
    
    func test007_extractPrivateKeyToPemAndDer() {
        let keyPair = VSCKeyPair()
        
        let pemData = VSCKeyPair.privateKey(toPEM: keyPair.privateKey())!
        XCTAssert(pemData.count > 0)
        let derData = VSCKeyPair.privateKey(toDER: keyPair.privateKey())!
        XCTAssert(derData.count > 0)
    }
    
    func test008_extractPrivateKeyWithPasswordToPemAndDer() {
        let password = "secret"
        let keyPair = VSCKeyPair()
        
        let pemData = VSCKeyPair.privateKey(toPEM: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(pemData.count > 0)
        let derData = VSCKeyPair.privateKey(toDER: keyPair.privateKey(), privateKeyPassword: password)!
        XCTAssert(derData.count > 0)
    }
    
    func test009_createMultipleKeyPairs() {
        let number = 10
        let keypairs = VSCKeyPair.generateMultipleKeys(UInt(number), keyPairType: VSCKeyType.FAST_EC_ED25519)
        XCTAssert(keypairs.count == number)
    }
}
