//
//  VirgilCryptoSwiftTests.swift
//  VirgilCryptoSwiftTests
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

import UIKit
import XCTest

class VC002_CryptorSwiftTests: XCTestCase {
    
    var toEncrypt: NSData! = nil
    
    override func setUp() {
        super.setUp()
        
        let message = NSString(string: "Secret message which is necessary to be encrypted.")
        self.toEncrypt = message.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
    }
    
    override func tearDown() {
        self.toEncrypt = nil
        super.tearDown()
    }
    
    func test001_createCryptor() {
        let cryptor = VSSCryptor()
        XCTAssertNotNil(cryptor, "VCCryptor instance should be created.");
    }
    
    func test002_keyBasedEncryptDecrypt() {
        // Generate a new key pair
        let keyPair = VSSKeyPair()
        // Generate a public key id
        let publicKeyId = NSUUID().UUIDString
        // Encrypt:
        // Create a cryptor instance
        let cryptor = VSSCryptor()
        // Add a key recepient to enable key-based encryption
        cryptor.addKeyRecepient(publicKeyId, publicKey: keyPair.publicKey())
        // Encrypt the data
        let encryptedData = cryptor.encryptData(self.toEncrypt, embedContentInfo: true)
        XCTAssertNotNil(encryptedData, "Plain data should be encrypted.")
        XCTAssertTrue(encryptedData!.length > 0, "The data encrypted with key-based encryption should have an actual content.");
    
        // Decrypt:
        // Create a completely new instance of the VCCryptor object
        let decryptor = VSSCryptor()
        // Decrypt data using key-based decryption
        let plainData = decryptor.decryptData(encryptedData!, publicKeyId: publicKeyId, privateKey: keyPair.privateKey(), keyPassword: nil)
        XCTAssertNotNil(plainData, "Encrypted data should be decrypted.")
        XCTAssertEqual(plainData!, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func test003_passwordBasedEncryptDecrypt() {
        // Encrypt:
        let password = "secret"
        // Create a cryptor instance
        let cryptor = VSSCryptor()
        // Add a password recepient to enable password-based encryption
        cryptor.addPasswordRecipient(password)
        // Encrypt the data
        let encryptedData = cryptor.encryptData(self.toEncrypt, embedContentInfo: true)
        XCTAssertNotNil(encryptedData, "Plain data should be encrypted.")
        XCTAssertTrue(encryptedData!.length > 0, "The data encrypted with password-based encryption should have an actual content.");
    
        // Decrypt:
        // Create a completely new instance of the VCCryptor object
        let decryptor = VSSCryptor()
        // Decrypt data using password-based decryption
        let plainData = decryptor.decryptData(encryptedData!, password: password)
        XCTAssertNotNil(plainData, "Encrypted data should be decrypted.")
        XCTAssertEqual(plainData!, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
}
