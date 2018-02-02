//
//  VSC008_TinyCipherTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC008_TinyCipherTests: XCTestCase {
    private var toEncrypt: Data!
    
    override func setUp() {
        self.toEncrypt = "Secret message which should be encrypted.".data(using: .utf8)
    }
    
    func test001_encryptDecrypt() {
        let keyPair = KeyPair()
        
        let cipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        try! cipher.encryptData(self.toEncrypt, recipientPublicKey: keyPair.publicKey())
        
        let packageCount = cipher.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cipher.package(at: i)
            encryptedData.append(package)
        }
        
        try! cipher.reset()
        
        let decipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decipher.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decipher.addPackage(package)
        }
        
        XCTAssert(decipher.packagesAccumulated())
        
        let decryptedData = try! decipher.decrypt(withRecipientPrivateKey: keyPair.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decipher.reset()
    }
    
    func test002_encryptSignVerifyDecrypt() {
        let keyPairRec = KeyPair()
        let keyPairSen = KeyPair()
        
        let cipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        try! cipher.encryptAndSign(self.toEncrypt, recipientPublicKey: keyPairRec.publicKey(), senderPrivateKey: keyPairSen.privateKey(), senderKeyPassword: nil)
        
        let packageCount = cipher.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cipher.package(at: i)
            encryptedData.append(package)
        }
        
        try! cipher.reset()
        
        let decipher = TinyCipher(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decipher.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decipher.addPackage(package)
        }
        
        XCTAssert(decipher.packagesAccumulated())
        
        let decryptedData = try! decipher.verifyAndDecrypt(withSenderPublicKey: keyPairSen.publicKey(), recipientPrivateKey: keyPairRec.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decipher.reset()
    }
}
