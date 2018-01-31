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
import VirgilCryptoApiImpl

class VSM003_CryptoFormatsTests: XCTestCase {
    private let crypto = VirgilCrypto()
    
    func testSignatureHash() {
        let keyPair = try! self.crypto.generateKeyPair()
        let signature = try! crypto.generateSignature(of: "test".data(using: .utf8)!, using: keyPair.privateKey)
        
        XCTAssert(signature.subdata(in: 0..<17) == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAIDBQA="))
    }
}
