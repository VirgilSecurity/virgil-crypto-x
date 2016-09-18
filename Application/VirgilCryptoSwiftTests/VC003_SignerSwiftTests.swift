//
//  VirgilCryptoSwiftTests.swift
//  VirgilCryptoSwiftTests
//
//  Created by Pavel Gorb on 9/23/15.
//  Copyright (c) 2015 VirgilSecurity. All rights reserved.
//

import UIKit
import XCTest

class VC003_SignerSwiftTests: XCTestCase {
    
    var toSign: Data! = nil
    
    override func setUp() {
        super.setUp()
        
        let message = NSString(string: "Message which is need to be signed.")
        self.toSign = message.data(using: String.Encoding.utf8.rawValue, allowLossyConversion:false)
    }
    
    override func tearDown() {
        self.toSign = nil
        super.tearDown()
    }
    
    func test001_createSigner() {
        let signer = VSSSigner()
        XCTAssertNotNil(signer, "VCSigner instance should be created.");
    }
    
    func test002_composeAndVerifySignature() {
        // Generate a new key pair
        let keyPair = VSSKeyPair()
    
        // Compose signature:
        // Create the signer
        let signer = VSSSigner()
        // Compose the signature
        var signature = Data()
        do {
            signature = try signer.sign(self.toSign, privateKey: keyPair.privateKey(), keyPassword: nil, error: ())
        }
        catch let error as NSError {
            XCTFail("Error composing the signature: \(error.localizedDescription)")
        }
        
        let verifier = VSSSigner()
        do {
            try verifier.verifySignature(signature, data: self.toSign, publicKey: keyPair.publicKey(), error: ())
        }
        catch let error as NSError {
            XCTFail("Error verification the signature: \(error.localizedDescription)")
        }
    }
    
}
