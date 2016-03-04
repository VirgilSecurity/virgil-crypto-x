//
//  VC005_ChunkCryptorSwiftTests.swift
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/3/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

import XCTest

let kPlainDataLength: Int = 5120
let kDesiredDataChunkLength: Int = 1024

class VC005_ChunkCryptorSwiftTests: XCTestCase {

    var toEncrypt: NSData! = nil
    
    override func setUp() {
        super.setUp()
        
        self.toEncrypt = self.randomDataWithBytes(kPlainDataLength)
    }
    
    override func tearDown() {
        self.toEncrypt = nil
        
        super.tearDown()
    }
    
    func test001_createCryptor() {
        let cryptor = VSSChunkCryptor()
        XCTAssertNotNil(cryptor, "VSSChunkCryptor instance should be created.");
    }
    
    func test002_keyBasedEncryptDecrypt() {
        // Generate a new key pair
        let keyPair = VSSKeyPair()
        // Generate a public key id
        let recipientId = NSUUID().UUIDString
        // Encrypt:
        // Create a cryptor instance
        let cryptor = VSSChunkCryptor()
        // Add a key recepient to enable key-based encryption
        do {
            try cryptor.addKeyRecipient(recipientId, publicKey: keyPair.publicKey(), error: ())
        }
        catch let error as NSError {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        var actualSize = 0
        let encryptedData = NSMutableData()
        do {
            var error: NSError? = nil

            actualSize = cryptor.startEncryptionWithPreferredChunkSize(kDesiredDataChunkLength, error: &error)
            if let err = error {
                XCTFail("Error starting chunk encryption: \(err.localizedDescription)")
            }
            
            for var offset = 0; offset < self.toEncrypt.length; offset += Int(actualSize) {
                let bytesPtr = self.toEncrypt.bytes + offset
                let mutBytes = UnsafeMutablePointer<UInt8>(bytesPtr)
                let chunk = NSData(bytesNoCopy:mutBytes, length: Int(actualSize), freeWhenDone: false)
                let encryptedChunk = try cryptor.processDataChunk(chunk)
                encryptedData.appendData(encryptedChunk)
            }
        }
        catch let error as NSError {
            XCTFail("Error during chunk encryption: \(error.localizedDescription)")
        }
        XCTAssertTrue(encryptedData.length > 0, "Encrypted data should contain actual data.");
        
        do {
            try cryptor.finish()
        }
        catch let error as NSError {
            XCTFail("Error finishing chunks processing: \(error.localizedDescription)")
        }
        
        var contentInfo = NSData()
        do {
            contentInfo = try cryptor.contentInfoWithError()
        }
        catch let error as NSError {
            XCTFail("Error getting content info from cryptor: \(error.localizedDescription)")
        }
        XCTAssertTrue(contentInfo.length > 0, "Content Info should contain necessary information.");
        
        let decryptor = VSSChunkCryptor()
        
        do {
            try decryptor.setContentInfo(contentInfo, error: ())
        }
        catch let error as NSError {
            XCTFail("Error setting content info: \(error.localizedDescription)")
        }
        
        actualSize = 0
        let plainData = NSMutableData()
        do {
            var error: NSError? = nil
            actualSize = decryptor.startDecryptionWithRecipientId(recipientId, privateKey: keyPair.privateKey(), keyPassword: nil, error: &error)
            if let err = error {
                XCTFail("Error starting chunk decryption: \(err.localizedDescription)")
            }
            
            for var offset = 0; offset < encryptedData.length; offset += Int(actualSize) {
                let bytesPtr = encryptedData.bytes + offset
                let mutBytes = UnsafeMutablePointer<UInt8>(bytesPtr)
                let chunk = NSData(bytesNoCopy:mutBytes, length: Int(actualSize), freeWhenDone: false)
                let decryptedChunk = try decryptor.processDataChunk(chunk)
                plainData.appendData(decryptedChunk)
            }
        }
        catch let error as NSError {
            XCTFail("Error during chunk decryption: \(error.localizedDescription)")
        }
        XCTAssertTrue(plainData.length > 0, "Decrypted data should contain actual data.")
        
        do {
            try decryptor.finish()
        }
        catch let error as NSError {
            XCTFail("Error finishing chunks processing: \(error.localizedDescription)")
        }
        
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func test003_passwordBasedEncryptDecrypt() {
        // Encrypt:
        let password = "secret"
        // Encrypt:
        // Create a cryptor instance
        let cryptor = VSSChunkCryptor()
        // Add a key recepient to enable key-based encryption
        do {
            try cryptor.addPasswordRecipient(password, error: ())
        }
        catch let error as NSError {
            print("Error adding password recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        var actualSize = 0
        let encryptedData = NSMutableData()
        do {
            var error: NSError? = nil
            actualSize = cryptor.startEncryptionWithPreferredChunkSize(kDesiredDataChunkLength, error: &error)
            if let err = error {
                XCTFail("Error starting chunk encryption: \(err.localizedDescription)")
            }
            
            for var offset = 0; offset < self.toEncrypt.length; offset += Int(actualSize) {
                let bytesPtr = self.toEncrypt.bytes + offset
                let mutBytes = UnsafeMutablePointer<UInt8>(bytesPtr)
                let chunk = NSData(bytesNoCopy:mutBytes, length: Int(actualSize), freeWhenDone: false)
                let encryptedChunk = try cryptor.processDataChunk(chunk)
                encryptedData.appendData(encryptedChunk)
            }
        }
        catch let error as NSError {
            XCTFail("Error during chunk encryption: \(error.localizedDescription)")
        }
        XCTAssertTrue(encryptedData.length > 0, "Encrypted data should contain actual data.");
        
        do {
            try cryptor.finish()
        }
        catch let error as NSError {
            XCTFail("Error finishing chunks processing: \(error.localizedDescription)")
        }
        
        var contentInfo = NSData()
        do {
            contentInfo = try cryptor.contentInfoWithError()
        }
        catch let error as NSError {
            XCTFail("Error getting content info from cryptor: \(error.localizedDescription)")
        }
        XCTAssertTrue(contentInfo.length > 0, "Content Info should contain necessary information.");
        
        let decryptor = VSSChunkCryptor()
        
        do {
            try decryptor.setContentInfo(contentInfo, error: ())
        }
        catch let error as NSError {
            XCTFail("Error setting content info: \(error.localizedDescription)")
        }
        
        actualSize = 0
        let plainData = NSMutableData()
        do {
            var error: NSError? = nil
            actualSize = decryptor.startDecryptionWithPassword(password, error: &error)
            if let err = error {
                XCTFail("Error starting chunk decryption: \(err.localizedDescription)")
            }
            
            for var offset = 0; offset < encryptedData.length; offset += Int(actualSize) {
                let bytesPtr = encryptedData.bytes + offset
                let mutBytes = UnsafeMutablePointer<UInt8>(bytesPtr)
                let chunk = NSData(bytesNoCopy:mutBytes, length: Int(actualSize), freeWhenDone: false)
                let decryptedChunk = try decryptor.processDataChunk(chunk)
                plainData.appendData(decryptedChunk)
            }
        }
        catch let error as NSError {
            XCTFail("Error during chunk decryption: \(error.localizedDescription)")
        }
        XCTAssertTrue(plainData.length > 0, "Decrypted data should contain actual data.")
        
        do {
            try decryptor.finish()
        }
        catch let error as NSError {
            XCTFail("Error finishing chunks processing: \(error.localizedDescription)")
        }
        
        XCTAssertEqual(plainData, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func randomDataWithBytes(length: Int) -> NSData {
        var array = Array<UInt8>(count: length, repeatedValue: 0)
        arc4random_buf(&array, length)
        return NSData(bytes: array, length: length)
    }


}
