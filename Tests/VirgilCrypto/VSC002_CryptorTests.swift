//
//  VSC002_CipherTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC002_CipherTests: XCTestCase {
    var toEncrypt: Data! = nil
    
    override func setUp() {
        super.setUp()
        
        let message = NSString(string: "Secret message which is necessary to be encrypted.")
        self.toEncrypt = message.data(using: String.Encoding.utf8.rawValue, allowLossyConversion: false)
    }
    
    override func tearDown() {
        self.toEncrypt = nil
        super.tearDown()
    }
    
    func test001_keyBasedEncryptDecrypt() {
        // Generate a new key pair
        let keyPair = KeyPair()
        // Generate a public key id
        let recipientId = UUID().uuidString
        // Encrypt:
        // Create a cipher instance
        let cipher = Cipher()
        // Add a key recepient to enable key-based encryption
        try! cipher.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey())
        
        // Encrypt the data
        var encryptedData = try! cipher.encryptData(self.toEncrypt, embedContentInfo: true)
        
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with key-based encryption should have an actual content.");
        
        // Decrypt:
        // Create a completely new instance of the VCCipher object
        let decipher = Cipher()
        // Decrypt data using key-based decryption
        let plainData = try! decipher.decryptData(encryptedData, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil)
        
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        // Encrypt:
        let password = "secret"
        // Create a cipher instance
        let cipher = Cipher()
        // Add a password recepient to enable password-based encryption
        try! cipher.addPasswordRecipient(password)
        
        // Encrypt the data
        var encryptedData = try! cipher.encryptData(self.toEncrypt, embedContentInfo: false)
        
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with password-based encryption should have an actual content.");
        
        var contentInfo = try! cipher.contentInfo()
        
        XCTAssertTrue(contentInfo.count > 0, "Content Info should contain necessary information.");
        // Decrypt:
        // Create a completely new instance of the VCCipher object
        let decipher = Cipher()
        try! decipher.setContentInfo(contentInfo)
        
        // Decrypt data using password-based decryption
        let plainData = try! decipher.decryptData(encryptedData, password: password)
        
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
}
