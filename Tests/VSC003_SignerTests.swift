//
//  VSC003_SignerTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC003_SignerTests: XCTestCase {
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
    
    func test001_composeAndVerifySignature() {
        // Generate a new key pair
        let keyPair = VSCKeyPair()
        
        // Compose signature:
        // Create the signer
        let signer = VSCSigner()
        // Compose the signature
        var signature = Data()
        do {
            signature = try signer.sign(self.toSign, privateKey: keyPair.privateKey(), keyPassword: nil)
        }
        catch let error as NSError {
            XCTFail("Error composing the signature: \(error.localizedDescription)")
        }
        
        let verifier = VSCSigner()
        do {
            try verifier.verifySignature(signature, data: self.toSign, publicKey: keyPair.publicKey())
        }
        catch let error as NSError {
            XCTFail("Error verification the signature: \(error.localizedDescription)")
        }
    }
}
