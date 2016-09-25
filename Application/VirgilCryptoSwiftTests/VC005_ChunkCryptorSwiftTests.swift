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

    var toEncrypt: Data! = nil
    
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
        let recipientId = UUID().uuidString
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
        
        var actualSize:Int = 0
        let encryptedData = NSMutableData()
        do {
            var error: NSError? = nil

            actualSize = cryptor.startEncryption(withPreferredChunkSize: kDesiredDataChunkLength, error: &error)
            if let err = error {
                XCTFail("Error starting chunk encryption: \(err.localizedDescription)")
            }
            
            
            for offset in stride(from:0, to: self.toEncrypt.count, by: actualSize) {
                let bytesPtr = self.toEncrypt.withUnsafeBytes({ (bytes:UnsafePointer<CChar>) -> UnsafePointer<CChar> in
                    return bytes + offset
                })
                
                let mutBytes = UnsafeMutablePointer(mutating: bytesPtr)
                let chunk = Data(bytesNoCopy: UnsafeMutablePointer(mutBytes), count: Int(actualSize), deallocator: .none)
                let encryptedChunk = try cryptor.processDataChunk(chunk)
                encryptedData.append(encryptedChunk)
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
        
        var contentInfo = Data()
        do {
            contentInfo = try cryptor.contentInfoWithError()
        }
        catch let error as NSError {
            XCTFail("Error getting content info from cryptor: \(error.localizedDescription)")
        }
        XCTAssertTrue(contentInfo.count > 0, "Content Info should contain necessary information.");
        
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
            actualSize = decryptor.startDecryption(withRecipientId: recipientId, privateKey: keyPair.privateKey(), keyPassword: nil, error: &error)
            if let err = error {
                XCTFail("Error starting chunk decryption: \(err.localizedDescription)")
            }
            
            for offset in stride(from:0, to: self.toEncrypt.count, by: actualSize) {
                let bytesPtr = encryptedData.bytes + offset
                let mutBytes = UnsafeMutableRawPointer(mutating: bytesPtr)
                let chunk = Data(bytesNoCopy: UnsafeMutableRawPointer(mutBytes), count: Int(actualSize), deallocator: .none)
                let decryptedChunk = try decryptor.processDataChunk(chunk)
                plainData.append(decryptedChunk)
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
        
        XCTAssertEqual(plainData as Data, self.toEncrypt, "Initial data and decrypted data should be equal.")
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
            actualSize = cryptor.startEncryption(withPreferredChunkSize: kDesiredDataChunkLength, error: &error)
            if let err = error {
                XCTFail("Error starting chunk encryption: \(err.localizedDescription)")
            }
            
            for offset in stride(from:0, to: self.toEncrypt.count, by: actualSize) {
                let bytesPtr = self.toEncrypt.withUnsafeBytes({ (bytes:UnsafePointer<CChar>) -> UnsafePointer<CChar> in
                    return bytes + offset
                })
                
                let mutBytes = UnsafeMutablePointer(mutating: bytesPtr)
                let chunk = Data(bytesNoCopy: UnsafeMutablePointer(mutBytes), count: Int(actualSize), deallocator: .none)
                let encryptedChunk = try cryptor.processDataChunk(chunk)
                encryptedData.append(encryptedChunk)
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
        
        var contentInfo = Data()
        do {
            contentInfo = try cryptor.contentInfoWithError()
        }
        catch let error as NSError {
            XCTFail("Error getting content info from cryptor: \(error.localizedDescription)")
        }
        XCTAssertTrue(contentInfo.count > 0, "Content Info should contain necessary information.");
        
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
            actualSize = decryptor.startDecryption(withPassword: password, error: &error)
            if let err = error {
                XCTFail("Error starting chunk decryption: \(err.localizedDescription)")
            }
            
            for offset in stride(from:0, to: self.toEncrypt.count, by: actualSize) {
                let bytesPtr = encryptedData.bytes + offset
                let mutBytes = UnsafeMutableRawPointer(mutating: bytesPtr)
                let chunk = Data(bytesNoCopy: UnsafeMutableRawPointer(mutBytes), count: Int(actualSize), deallocator: .none)
                let decryptedChunk = try decryptor.processDataChunk(chunk)
                plainData.append(decryptedChunk)
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
        
        XCTAssertEqual(plainData as Data, self.toEncrypt, "Initial data and decrypted data should be equal.")
    }
    
    func randomDataWithBytes(_ length: Int) -> Data {
        var array = Array<UInt8>(repeating: 0, count: length)
        arc4random_buf(&array, length)
        return Data(bytes: UnsafePointer<UInt8>(array), count: length)
    }


}
