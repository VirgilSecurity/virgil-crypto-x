//
//  VSC006_StreamSignerTests.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/13/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import XCTest
import VirgilCrypto

class VSC006_StreamSignerTests: XCTestCase {
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
        let signer = VSCStreamSigner()
        // Compose the signature
        var signature = Data()
        let sis = InputStream(data: self.toSign)
        signature = try! signer.signStreamData(sis, privateKey: keyPair.privateKey(), keyPassword: nil)
        
        let verifier = VSCStreamSigner()
        let vis = InputStream(data: self.toSign)
        try! verifier.verifySignature(signature, from: vis, publicKey: keyPair.publicKey())
    }
}
