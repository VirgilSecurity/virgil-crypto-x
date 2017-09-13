//
//  VSC005_ChunkCryptorTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

let kPlainDataLength: Int = 5120
let kDesiredDataChunkLength: Int = 1024

class VSC005_ChunkCryptorTests: XCTestCase {
    var toEncrypt: Data! = nil
    
    override func setUp() {
        super.setUp()
        
        self.toEncrypt = self.randomDataWithBytes(kPlainDataLength)
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
        // Create a cryptor instance
        let cryptor = VSCChunkCryptor()
        // Add a key recepient to enable key-based encryption
        do {
            try cryptor.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey(), error: ())
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        var error: NSError?
        cryptor.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true, error: &error)
        
        if error != nil {
            XCTFail()
        }
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decryptor = VSCChunkCryptor()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        decryptor.decrypt(from: idecstream, to: odecstream, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil, error: &error)
        if error != nil {
            XCTFail()
        }
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        let passwd = "secret"
        // Create a cryptor instance
        let cryptor = VSCChunkCryptor()
        // Add a key recepient to enable key-based encryption
        do {
            try cryptor.addPasswordRecipient(passwd, error: ())
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        var error: NSError?
        cryptor.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true, error: &error)
        
        if error != nil {
            XCTFail()
        }
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decryptor = VSCChunkCryptor()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        decryptor.decrypt(from: idecstream, to: odecstream, password: passwd, error: &error)
        if error != nil {
            XCTFail()
        }
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func randomDataWithBytes(_ length: Int) -> Data {
        var array = Array<UInt8>(repeating: 0, count: length)
        arc4random_buf(&array, length)
        return Data(bytes: UnsafePointer<UInt8>(array), count: length)
    }
}
