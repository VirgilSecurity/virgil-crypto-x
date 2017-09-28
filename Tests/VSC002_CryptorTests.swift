//
//  VSC002_CryptorTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC002_CryptorTests: XCTestCase {
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
        let keyPair = VSCKeyPair()
        // Generate a public key id
        let recipientId = UUID().uuidString
        // Encrypt:
        // Create a cryptor instance
        let cryptor = VSCCryptor()
        // Add a key recepient to enable key-based encryption
        do {
            try cryptor.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey())
        }
        catch let error as NSError {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        // Encrypt the data
        var encryptedData = Data()
        do {
            encryptedData = try cryptor.encryptData(self.toEncrypt, embedContentInfo: true)
        }
        catch let error as NSError {
            print("Error encrypting data: \(error.localizedDescription)")
            XCTFail()
        }
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with key-based encryption should have an actual content.");
        
        // Decrypt:
        // Create a completely new instance of the VCCryptor object
        let decryptor = VSCCryptor()
        // Decrypt data using key-based decryption
        var plainData = Data()
        do {
            plainData = try decryptor.decryptData(encryptedData, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil)
        }
        catch let error as NSError {
            print("Error decrypting data: \(error.localizedDescription)")
            XCTFail()
        }
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        // Encrypt:
        let password = "secret"
        // Create a cryptor instance
        let cryptor = VSCCryptor()
        // Add a password recepient to enable password-based encryption
        do {
            try cryptor.addPasswordRecipient(password)
        }
        catch let error as NSError {
            print("Error adding password recipient: \(error.localizedDescription)")
            XCTFail()
        }
        // Encrypt the data
        var encryptedData = Data()
        do {
            encryptedData = try cryptor.encryptData(self.toEncrypt, embedContentInfo: false)
        }
        catch let error as NSError {
            print("Error encrypting data: \(error.localizedDescription)")
            XCTFail()
        }
        XCTAssertTrue(encryptedData.count > 0, "The data encrypted with password-based encryption should have an actual content.");
        
        var contentInfo = Data()
        do {
            contentInfo = try cryptor.contentInfo()
        }
        catch let error as NSError {
            print("Error getting content info from cryptor: \(error.localizedDescription)")
            XCTFail()
        }
        XCTAssertTrue(contentInfo.count > 0, "Content Info should contain necessary information.");
        // Decrypt:
        // Create a completely new instance of the VCCryptor object
        let decryptor = VSCCryptor()
        do {
            try decryptor.setContentInfo(contentInfo)
        }
        catch let error as NSError {
            print("Error setting content info to decryptor: \(error.localizedDescription)")
            XCTFail()
        }
        // Decrypt data using password-based decryption
        var plainData = Data()
        do {
            plainData = try decryptor.decryptData(encryptedData, password: password)
        }
        catch let error as NSError {
            print("Error decrypting data: \(error.localizedDescription)")
            XCTFail()
        }
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
}
