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
    
    private static let allKeyTypes: [KeyPairType] = [.curve25519, .ed25519, .secp256r1, .rsa2048, .curve25519Round5Ed25519Falcon, .curve25519Ed25519, .curve25519Round5]
    private static let signingKeyTypes: [KeyPairType] = [.ed25519, .secp256r1, .rsa2048, .curve25519Round5Ed25519Falcon, .curve25519Ed25519]

    func test01__key_generation__generate_one_key__should_succeed() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.allKeyTypes {
                try self.checkKeyGeneration(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.allKeyTypes {
                try self.checkKeyImport(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.allKeyTypes {
                try self.checkEncryption(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkSignature(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    private func checkSignAndEncrypt(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair3 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let encrypted = try crypto.signAndEncrypt(data, with: keyPair1.privateKey, for: [keyPair1.publicKey, keyPair2.publicKey])
        
        let decrypted = try crypto.decryptAndVerify(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
        
        XCTAssert(data == decrypted)
        
        do {
             _ = try crypto.decryptAndVerify(encrypted, with: keyPair3.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
            XCTFail()
        }
        catch { }
        
        do {
            _ = try crypto.decryptAndVerify(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair3.publicKey])
            XCTFail()
        }
        catch { }
    }
    
    func test05__sign_and_encrypt__some_data__should_decrypt_and_verify() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkSignAndEncrypt(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkStreamSign(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.allKeyTypes {
                try self.checkStreamEncryption(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
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
            
            for keyType in VSM001_CryptoTests.allKeyTypes {
                try self.checkGenerateKeyUsingSeed(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test09__multithread_sign_and_encrypt__same_key_should_work() {
        do {
            let queue1 = DispatchQueue(label: "1")
            let queue2 = DispatchQueue(label: "2")

            let crypto = try VirgilCrypto()

            let keyPair = try crypto.generateKeyPair()
            let data = UUID().uuidString.data(using: .utf8)!

            let task = {
                for _ in 0..<100 {
                    let encryptedData = try crypto.signAndEncrypt(data, with: keyPair.privateKey, for: [keyPair.publicKey])
                    let decryptedData = try crypto.decryptAndVerify(encryptedData, with: keyPair.privateKey, usingOneOf: [keyPair.publicKey])

                    XCTAssert(data == decryptedData)
                }
            }

            let dispatchGroup = DispatchGroup()

            queue1.async {
                dispatchGroup.enter()
                try! task()
                dispatchGroup.leave()
            }

            queue2.async {
                dispatchGroup.enter()
                try! task()
                dispatchGroup.leave()
            }

            dispatchGroup.wait()
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    private func checkKeyExportImport(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair = try crypto.generateKeyPair(ofType: keyPairType)
        
        let publicKeyData = try crypto.exportPublicKey(keyPair.publicKey)
        let privateKeyData = try crypto.exportPrivateKey(keyPair.privateKey)
        
        let publicKey = try crypto.importPublicKey(from: publicKeyData)
        let privateKey = try crypto.importPrivateKey(from: privateKeyData).privateKey
        
        _ = try crypto.signAndEncrypt(UUID().uuidString.data(using: .utf8)!, with: privateKey, for: [publicKey])
    }
    
    func test10__imprort_export_key__random_key__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkKeyExportImport(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail()
        }
    }
    
    private func checkAuthEncrypt(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair3 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let encrypted = try crypto.authEncrypt(data, with: keyPair1.privateKey, for: [keyPair2.publicKey], enablePadding: false)
        let decrypted = try crypto.authDecrypt(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair1.publicKey])
        
        XCTAssert(data == decrypted)
        
        do {
             _ = try crypto.authDecrypt(encrypted, with: keyPair3.privateKey, usingOneOf: [keyPair1.publicKey])
            XCTFail()
        }
        catch { }
        
        do {
            _ = try crypto.authDecrypt(encrypted, with: keyPair2.privateKey, usingOneOf: [keyPair3.publicKey])
            XCTFail()
        }
        catch { }
    }
    
    func test11__auth_encrypt__random_data__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkAuthEncrypt(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    private func checkAuthEncryptStream(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair3 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "testData", withExtension: "txt")!
        let inputStream = InputStream(url: testFileURL)!
        let data = try Data(contentsOf: testFileURL)
        
        let fileSize = try FileManager().attributesOfItem(atPath: testFileURL.path)[FileAttributeKey.size] as! Int
        
        let outputStream = OutputStream.toMemory()
        
        try crypto.authEncrypt(inputStream, streamSize: fileSize, to: outputStream, with: keyPair1.privateKey, for: [keyPair1.publicKey, keyPair2.publicKey])
        
        let encryptedData = outputStream.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        
        let inputStream1 = InputStream(data: encryptedData)
        let inputStream2 = InputStream(data: encryptedData)
        let inputStream3 = InputStream(data: encryptedData)
        
        let outputStream1 = OutputStream.toMemory()
        let outputStream2 = OutputStream.toMemory()
        let outputStream3 = OutputStream.toMemory()
        
        try crypto.authDecrypt(inputStream1, to: outputStream1, with: keyPair1.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
        
        let decrtyptedData = outputStream1.property(forKey: Stream.PropertyKey.dataWrittenToMemoryStreamKey) as! Data
        
        XCTAssert(data == decrtyptedData)
        
        do {
            _ = try crypto.authDecrypt(inputStream2, to: outputStream2, with: keyPair3.privateKey, usingOneOf: [keyPair1.publicKey, keyPair2.publicKey])
            XCTFail()
        }
        catch { }
        
        do {
            _ = try crypto.authDecrypt(inputStream3, to: outputStream3, with: keyPair2.privateKey, usingOneOf: [keyPair3.publicKey])
            XCTFail()
        }
        catch { }
    }
    
    func test12__auth_encrypt__stream__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkAuthEncryptStream(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    private func checkAuthEncryptDeprecated(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let encrypted1 = try crypto.authEncrypt(data, with: keyPair1.privateKey, for: [keyPair2.publicKey], enablePadding: false)
        let encrypted2 = try crypto.signAndEncrypt(data, with: keyPair1.privateKey, for: [keyPair2.publicKey])
        
        let decrypted1 = try crypto.authDecrypt(encrypted1,
                                                with: keyPair2.privateKey,
                                                usingOneOf: [keyPair1.publicKey],
                                                allowNotEncryptedSignature: true)
        let decrypted2 = try crypto.authDecrypt(encrypted2,
                                                with: keyPair2.privateKey,
                                                usingOneOf: [keyPair1.publicKey],
                                                allowNotEncryptedSignature: true)
        
        XCTAssert(data == decrypted1)
        XCTAssert(data == decrypted2)
    }
    
    func test13__auth_encrypt__deprecated__should_work() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkAuthEncryptDeprecated(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
    
    private func checkAuthEncryptPadding(crypto: VirgilCrypto, keyPairType: KeyPairType) throws {
        let data = UUID().uuidString.data(using: .utf8)!
        
        let keyPair1 = try crypto.generateKeyPair(ofType: keyPairType)
        let keyPair2 = try crypto.generateKeyPair(ofType: keyPairType)
        
        let encrypted1 = try crypto.authEncrypt(data, with: keyPair1.privateKey, for: [keyPair2.publicKey])
        let encrypted2 = try crypto.signAndEncrypt(data, with: keyPair1.privateKey, for: [keyPair2.publicKey])
        
        let decrypted1 = try crypto.authDecrypt(encrypted1, with: keyPair2.privateKey, usingOneOf: [keyPair1.publicKey], allowNotEncryptedSignature: true)
        let decrypted2 = try crypto.authDecrypt(encrypted2, with: keyPair2.privateKey, usingOneOf: [keyPair1.publicKey], allowNotEncryptedSignature: true)
        
        XCTAssert(data == decrypted1)
        XCTAssert(data == decrypted2)
    }
    
    func test14__auth_encrypt__padding__should_match() {
        do {
            let crypto = try VirgilCrypto()
            
            for keyType in VSM001_CryptoTests.signingKeyTypes {
                try self.checkAuthEncryptPadding(crypto: crypto, keyPairType: keyType)
            }
        }
        catch {
            XCTFail(error.localizedDescription)
        }
    }
}
