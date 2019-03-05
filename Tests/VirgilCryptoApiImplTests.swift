//
// Copyright (C) 2015-2019 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import XCTest
@testable import VirgilCryptoApiImpl

class VirgilCryptoApiImplTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func test01__key_generation__generate_one_key__should_succeed() {
        do {
            let crypto = try VirgilCrypto()
            
            _ = try crypto.generateKeyPair(ofType: .ed25519)
        }
        catch {
            XCTFail()
        }
    }
    
    func test02__private_key_import__ed_key__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            let keyPair = try crypto.generateKeyPair(ofType: .ed25519)
            
            let data = try crypto.exportPrivateKey(keyPair.privateKey)
            
            let privateKey = try crypto.importPrivateKey(from: data)
            
            XCTAssert(keyPair.privateKey.identifier == privateKey.identifier)
        }
        catch {
            XCTFail()
        }
    }
    
    func test03__private_key_import__rsa_key__should_match() {
        
    }
    
    func test04__public_key_import__ed_key__should_match() {
        
    }
    
    func test05__public_key_import__rsa_key__should_match() {
        
    }
    
    func test06__encryption__some_data__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            let keyPair = try crypto.generateKeyPair(ofType: .ed25519)
            
            let data = UUID().uuidString.data(using: .utf8)!
            
            let encryptedData = try crypto.encrypt(data, for: [keyPair.publicKey])
            
            let decryptedData = try crypto.decrypt(encryptedData, with: keyPair.privateKey)
            
            XCTAssert(encryptedData == decryptedData)
        }
        catch {
            XCTFail()
        }
    }

}
