//
//  VSM003_CryptoFormatsTests.swift
//  VirgilCryptoApiImpl
//
//  Created by Oleksandr Deundiak on 1/31/18.
//  Copyright © 2018 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto
@testable import VirgilCryptoApiImpl

class VSM003_CryptoFormatsTests: XCTestCase {
    func test001_SignatureHash() {
        let crypto = VirgilCrypto()
        let keyPair = try! crypto.generateKeyPair()
        let signature = try! crypto.generateSignature(of: "test".data(using: .utf8)!, using: keyPair.privateKey)
        
        XCTAssert(signature.subdata(in: 0..<17) == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAIDBQA="))
    }
    
    func test002_PrivateKeyIsDER() {
        let crypto = VirgilCrypto()
        let keyPair1 = try! crypto.generateKeyPair()
        
        XCTAssert(VSCKeyPair.privateKey(toDER: keyPair1.privateKey.rawKey)! == keyPair1.privateKey.rawKey)
        
        let keyPair2 = try! crypto.generateMultipleKeyPairs(numberOfKeyPairs: 1)[0]
        
        XCTAssert(VSCKeyPair.privateKey(toDER: keyPair2.privateKey.rawKey)! == keyPair2.privateKey.rawKey)
        
        let privateKey1 = try! crypto.importPrivateKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1DNENBUUF3QlFZREsyVndCQ0lFSUg4bnIyV05nblkya1ZScjRValp4UnJWVGpiMW4wWGdBZkhOWE1ocVkwaVAKLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQo=")!)
        
        XCTAssert(VSCKeyPair.privateKey(toDER: privateKey1.rawKey)! == privateKey1.rawKey)
        
        let privateKey2 = try! crypto.importPrivateKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUdoTUYwR0NTcUdTSWIzRFFFRkRUQlFNQzhHQ1NxR1NJYjNEUUVGRERBaUJCQ3kzSkk3V0VDcGVHZGFIdEc2CktHcjRBZ0lkWXpBS0JnZ3Foa2lHOXcwQ0NqQWRCZ2xnaGtnQlpRTUVBU29FRUp1Wlpqb0oyZGJGdUpZN0ZNSisKN3g0RVFEcnRpZjNNb29rQk5PRTBUaGZmSEtrV0R3K3lvZ0ZRRk1RRFJtU0kwSXl2T2w4RTVnck5QcFNxU3dQNApIL2lzYzJvQVJzSW03alVRQXkrQjl5aTRZK3c9Ci0tLS0tRU5EIEVOQ1JZUFRFRCBQUklWQVRFIEtFWS0tLS0tCg==")!, password: "qwerty")
        
        XCTAssert(VSCKeyPair.privateKey(toDER: privateKey2.rawKey)! == privateKey2.rawKey)
    }
    
    func test003_PublicKeyIsDER() {
        let crypto = VirgilCrypto()
        let keyPair1 = try! crypto.generateKeyPair()
        
        XCTAssert(VSCKeyPair.publicKey(toDER: keyPair1.publicKey.rawKey)! == keyPair1.publicKey.rawKey)
        
        let keyPair2 = try! crypto.generateMultipleKeyPairs(numberOfKeyPairs: 1)[0]
        
        XCTAssert(VSCKeyPair.publicKey(toDER: keyPair2.publicKey.rawKey)! == keyPair2.publicKey.rawKey)
        
        let publicKey = try! crypto.importPublicKey(from: Data(base64Encoded: "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQXYycWRHa0w2RmRxc0xpLzdPQTA1NjJPOVYvVDhFN3F6RmF0RjZMcW9TY3M9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo=")!)

        XCTAssert(VSCKeyPair.publicKey(toDER: publicKey.rawKey)! == publicKey.rawKey)
    }
    
    func test004_PrivateKeyIdentifierIsCorrect() {
        let crypto1 = VirgilCrypto()
        let keyPair1 = try! crypto1.generateKeyPair()
        
        XCTAssert(VSCHash(algorithm: .SHA512).hash(keyPair1.publicKey.rawKey).subdata(in: 0..<8) == keyPair1.publicKey.identifier)
        
        let crypto2 = VirgilCrypto(useSHA256Fingerprints: true)
        let keyPair2 = try! crypto2.generateKeyPair()
        
        XCTAssert(VSCHash(algorithm: .SHA256).hash(keyPair2.publicKey.rawKey) == keyPair2.publicKey.identifier)
    }
    
    func test005_PublicKeyIdentifierIsCorrect() {
        let crypto1 = VirgilCrypto()
        let keyPair1 = try! crypto1.generateKeyPair()
        
        let publicKey1 = try! crypto1.extractPublicKey(from: keyPair1.privateKey)
        
        XCTAssert(publicKey1.identifier == keyPair1.publicKey.identifier)
        XCTAssert(publicKey1.rawKey == keyPair1.publicKey.rawKey)
        
        XCTAssert(VSCHash(algorithm: .SHA512).hash(keyPair1.publicKey.rawKey).subdata(in: 0..<8) == keyPair1.publicKey.identifier)
        
        let crypto2 = VirgilCrypto(useSHA256Fingerprints: true)
        let keyPair2 = try! crypto2.generateKeyPair()
        
        let publicKey2 = try! crypto2.extractPublicKey(from: keyPair2.privateKey)
        
        XCTAssert(publicKey2.identifier == keyPair2.publicKey.identifier)
        XCTAssert(publicKey2.rawKey == keyPair2.publicKey.rawKey)
        
        XCTAssert(VSCHash(algorithm: .SHA256).hash(keyPair2.publicKey.rawKey) == keyPair2.publicKey.identifier)
    }
}
