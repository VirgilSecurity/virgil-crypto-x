//
//  VCKeyPairSwiftTests.swift
//  VirgilCryptoSwiftTests
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

import UIKit
import XCTest

class VC001_KeyPairSwiftTests: XCTestCase {
    
    func test001_createKeyPair() {
        let keyPair = VCKeyPair()
        XCTAssertNotNil(keyPair, "VCKeyPair instance should be created.");
        XCTAssertNotNil(keyPair.publicKey(), "Public key should be generated for the new key pair.")
        XCTAssertNotNil(keyPair.privateKey(), "Private key should be generated for the new key pair.")
        XCTAssertTrue(keyPair.publicKey().length > 0, "Public key should have actual content.");
        XCTAssertTrue(keyPair.privateKey().length > 0, "Private key should have actual content.");
        
        if let keyString = NSString(data: keyPair.privateKey(), encoding: NSUTF8StringEncoding) {
            let range = keyString.rangeOfString("ENCRYPTED", options: [.LiteralSearch, .CaseInsensitiveSearch])
            XCTAssertTrue(range.length == 0, "Private key should be generated in plain form.");
        }
    }
    
    func test002_createKeyPairWithPassword() {
        let password = "secret"
        let keyPair = VCKeyPair(password: password)
        XCTAssertNotNil(keyPair, "VCKeyPair instance should be created.");
        XCTAssertNotNil(keyPair.publicKey(), "Public key should be generated for the new key pair.")
        XCTAssertNotNil(keyPair.privateKey(), "Private key should be generated for the new key pair.")
        XCTAssertTrue(keyPair.publicKey().length > 0, "Public key should be generated for the new key pair.");
        XCTAssertTrue(keyPair.privateKey().length > 0, "Private key should be generated for the new key pair.");
    
        if let keyString = NSString(data: keyPair.privateKey(), encoding: NSUTF8StringEncoding) {
            let range = keyString.rangeOfString("ENCRYPTED", options: [.LiteralSearch, .CaseInsensitiveSearch])
            XCTAssertTrue(range.length != 0, "Private key should be generated protected by the password provided to initializer.");
        }
    }
        
}
