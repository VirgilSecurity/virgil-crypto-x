//
//  VSC005_ChunkCipherTests.swift
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

class VSC005_ChunkCipherTests: XCTestCase {
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
        let keyPair = KeyPair()
        // Generate a public key id
        let recipientId = UUID().uuidString
        // Create a cipher instance
        let cipher = ChunkCipher()
        // Add a key recepient to enable key-based encryption
        do {
            try cipher.addKeyRecipient(recipientId.data(using: .utf8)!, publicKey: keyPair.publicKey())
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        try! cipher.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true)
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decipher = ChunkCipher()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        try! decipher.decrypt(from: idecstream, to: odecstream, recipientId: recipientId.data(using: .utf8)!, privateKey: keyPair.privateKey(), keyPassword: nil)
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func test002_passwordBasedEncryptDecrypt() {
        let passwd = "secret"
        // Create a cipher instance
        let cipher = ChunkCipher()
        // Add a key recepient to enable key-based encryption
        do {
            try cipher.addPasswordRecipient(passwd)
        }
        catch {
            print("Error adding key recipient: \(error.localizedDescription)")
            XCTFail()
        }
        
        let istream = InputStream(data: self.toEncrypt)
        let ostream = OutputStream.toMemory()
        
        try! cipher.encryptData(from: istream, to: ostream, preferredChunkSize: kDesiredDataChunkLength, embedContentInfo: true)
        
        let encryptedData = ostream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        XCTAssert(encryptedData.count > 0)
        
        let decipher = ChunkCipher()
        
        let idecstream = InputStream(data: encryptedData)
        let odecstream = OutputStream.toMemory()
        
        try! decipher.decrypt(from: idecstream, to: odecstream, password: passwd)
        
        let plainData = odecstream.property(forKey: .dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(plainData == self.toEncrypt)
    }
    
    func randomDataWithBytes(_ length: Int) -> Data {
        var array = Array<UInt8>(repeating: 0, count: length)
        arc4random_buf(&array, length)
        return Data(bytes: UnsafePointer<UInt8>(array), count: length)
    }
}
