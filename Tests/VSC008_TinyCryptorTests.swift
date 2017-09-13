//
//  VSC008_TinyCryptorTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC008_TinyCryptorTests: XCTestCase {
    private var toEncrypt: Data!
    
    override func setUp() {
        self.toEncrypt = "Secret message which should be encrypted.".data(using: .utf8)
    }
    
    func test001_encryptDecrypt() {
        let keyPair = VSCKeyPair()
        
        let cryptor = VSCTinyCryptor(packageSize: .shortSMSPackageSize)
        
        try! cryptor.encryptData(self.toEncrypt, recipientPublicKey: keyPair.publicKey())
        
        let packageCount = cryptor.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cryptor.package(at: i)
            encryptedData.append(package)
        }
        
        try! cryptor.reset()
        
        let decryptor = VSCTinyCryptor(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decryptor.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decryptor.addPackage(package)
        }
        
        XCTAssert(decryptor.packagesAccumulated())
        
        let decryptedData = try! decryptor.decrypt(withRecipientPrivateKey: keyPair.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decryptor.reset()
    }
    
    func test002_encryptSignVerifyDecrypt() {
        let keyPairRec = VSCKeyPair()
        let keyPairSen = VSCKeyPair()
        
        let cryptor = VSCTinyCryptor(packageSize: .shortSMSPackageSize)
        
        try! cryptor.encryptAndSign(self.toEncrypt, recipientPublicKey: keyPairRec.publicKey(), senderPrivateKey: keyPairSen.privateKey(), senderKeyPassword: nil)
        
        let packageCount = cryptor.packageCount()
        XCTAssert(packageCount != 0)
        
        var encryptedData = Data()
        for i in 0..<packageCount {
            let package = try! cryptor.package(at: i)
            encryptedData.append(package)
        }
        
        try! cryptor.reset()
        
        let decryptor = VSCTinyCryptor(packageSize: .shortSMSPackageSize)
        
        let len = min(encryptedData.count, decryptor.packageSize)
        
        for i in stride(from: 0, to: encryptedData.count-1, by: len) {
            let package = encryptedData.subdata(in: Range(uncheckedBounds: (i, min(i + len, encryptedData.count))))
            try! decryptor.addPackage(package)
        }
        
        XCTAssert(decryptor.packagesAccumulated())
        
        let decryptedData = try! decryptor.verifyAndDecrypt(withSenderPublicKey: keyPairSen.publicKey(), recipientPrivateKey: keyPairRec.privateKey(), recipientKeyPassword: nil)
        XCTAssert(decryptedData == self.toEncrypt)
        
        try! decryptor.reset()
    }
}
