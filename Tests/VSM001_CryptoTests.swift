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
import VirgilCrypto

class VSM001_CryptoTests: XCTestCase {

    override func setUp() {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }
    
    private func checkKeyGeneration(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair = try crypto.generateKeyPair(ofType: keyPairType)
        
        XCTAssert(keyPair.privateKey.identifier == keyPair.publicKey.identifier)
    }

    func test01__key_generation__generate_one_key__should_succeed() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.curve25519, KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkKeyGeneration(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkKeyImport(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair = try crypto.generateKeyPair(ofType: keyPairType)
        
        let data1 = try crypto.exportPrivateKey(keyPair.privateKey)
        
        let privateKey = try crypto.importPrivateKey(from: data1)
        
        XCTAssert(keyPair.privateKey.identifier == privateKey.identifier)
        
        let data2 = try crypto.exportPublicKey(keyPair.publicKey)
        
        let publicKey = try crypto.importPublicKey(from: data2)
        
        XCTAssert(keyPair.publicKey.identifier == publicKey.identifier)
    }
    
    func test02__key_import__all_keys__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.curve25519, KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkKeyImport(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkEncryption(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let data = UUID().uuidString.data(using: .utf8)!
        
        let encryptedData = try crypto.encrypt(data, for: [keyPair1.publicKey])
        
        let decryptedData = try crypto.decrypt(encryptedData, with: keyPair1.privateKey)
        
        XCTAssert(data == decryptedData)
        
        do {
            _ = try crypto.decrypt(encryptedData, with: keyPair2.privateKey)
            XCTFail()
        }
        catch { }
    }
    
    func test03__encryption__some_data__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.curve25519, KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkEncryption(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkSignature(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let data = UUID().uuidString.data(using: .utf8)!

        let signature = try crypto.generateSignature(of: data, using: keyPair1.privateKey)
        
        XCTAssert(try! crypto.verifySignature(signature, of: data, with: keyPair1.publicKey))
        XCTAssert(!(try! crypto.verifySignature(signature, of: data, with: keyPair2.publicKey)))
    }

    func test04__signature__some_data__should_verify() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkSignature(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkSignThenEncrypt(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair3 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let encrypted = try crypto.signThenEncrypt(data, with: keyPair1.privateKey, for: [keyPair1.publicKey, keyPair2.publicKey])
        
        let decrypted = try crypto.decryptThenVerify(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
        
        XCTAssert(data == decrypted)
        
        do {
             _ = try crypto.decryptThenVerify(encrypted, with: keyPair3.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
            XCTFail()
        }
        catch { }
        
        do {
            _ = try crypto.decryptThenVerify(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair3.publicKey])
            XCTFail()
        }
        catch { }
    }
    
    func test05__sign_then_encrypt__some_data__should_decrypt_then_verify() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkSignThenEncrypt(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkStreamSign(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "testData", withExtension: "txt")!
        let inputStream = InputStream(url: testFileURL)!
        
        let signature = try crypto.generateStreamSignature(of: inputStream, using: keyPair1.privateKey)
        
        let verifyStream1 = InputStream(url: testFileURL)!
        let verifyStream2 = InputStream(url: testFileURL)!

        XCTAssert(try! crypto.verifyStreamSignature(signature, of: verifyStream1, with: keyPair1.publicKey))
        XCTAssert(!(try! crypto.verifyStreamSignature(signature, of: verifyStream2, with: keyPair2.publicKey)))
    }
    
    func test06__sign_stream__file__should_verify() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkStreamSign(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkStreamEncryption(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "testData", withExtension: "txt")!
        let inputStream = InputStream(url: testFileURL)!
        let data = try Data(contentsOf: testFileURL)
        
        let outputStream = OutputStream.toMemory()
        
        try crypto.encrypt(inputStream, to: outputStream, for: [keyPair1.publicKey])
        
        let encryptedData = outputStream.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        
        let inputStream1 = InputStream(data: encryptedData)
        let inputStream2 = InputStream(data: encryptedData)
        
        let outputStream1 = OutputStream.toMemory()
        let outputStream2 = OutputStream.toMemory()
        
        try crypto.decrypt(inputStream1, to: outputStream1, with: keyPair1.privateKey)
        
        let decrtyptedData = outputStream1.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(data == decrtyptedData)
        
        do {
            try crypto.decrypt(inputStream2, to: outputStream2, with: keyPair2.privateKey)
            XCTFail()
        }
        catch { }
    }
    
    func test07__encrypt_stream__file__should_decrypt() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.curve25519, KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkStreamEncryption(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkGenerateKeyUsingSeed(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let seed = try crypto.generateRandomData(ofSize: 32)
        
        let keyId = try crypto.generateKeyPair(ofType: keyPairType, usingSeed: seed).identifier
        
        for _ in 0..<5 {
            let keyPair = try crypto.generateKeyPair(ofType: keyPairType, usingSeed: seed)
            
            XCTAssert(keyPair.privateKey.identifier == keyId)
            XCTAssert(keyPair.privateKey.identifier == keyPair.publicKey.identifier)
        }
    }
    
    func test08__generate_key_using_seed__fixed_seed__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in [KeyPairType.curve25519, KeyPairType.ed25519, KeyPairType.rsa2048] {
                try self.checkStreamEncryption(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
}
