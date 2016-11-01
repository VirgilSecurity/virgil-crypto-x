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
        let keyPair = VSCKeyPair()
        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should have actual content.");
        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should have actual content.");
        
        if let keyString = NSString(data: keyPair.privateKey(), encoding: String.Encoding.utf8.rawValue) {
            let range = keyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive])
            XCTAssertTrue(range.length == 0, "Private key should be generated in plain form.");
        }
    }
    
    func test002_createKeyPairWithPassword() {
//        let password = "secret"
//        let keyPair = VSCKeyPair(password: password)
//        XCTAssertTrue(keyPair.publicKey().count > 0, "Public key should be generated for the new key pair.");
//        XCTAssertTrue(keyPair.privateKey().count > 0, "Private key should be generated for the new key pair.");
//    
//        if let keyString = NSString(data: keyPair.privateKey(), encoding: String.Encoding.utf8.rawValue) {
//            let range = keyString.range(of: "ENCRYPTED", options: [.literal, .caseInsensitive])
//            XCTAssertTrue(range.length != 0, "Private key should be generated protected by the password provided to initializer.");
//        }
    }
        
}
