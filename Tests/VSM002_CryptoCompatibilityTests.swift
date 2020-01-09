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
import VirgilCryptoFoundation

class VSM002_CryptoCompatibilityTests: XCTestCase {
    private let crypto = try! VirgilCrypto(useSHA256Fingerprints: true)
    private var testsDict: Dictionary<String, Any>!
    
    override func setUp() {
        super.setUp()
        
        let testFileURL = Bundle(for: type(of: self)).url(forResource: "crypto_compatibility_data", withExtension: "json")!
        let testFileData = try! Data(contentsOf: testFileURL)
        
        self.testsDict = try! JSONSerialization.jsonObject(with: testFileData, options: JSONSerialization.ReadingOptions.init(rawValue: 0)) as! Dictionary<String, Any>
    }
    
    func test001_CheckNumberOfTestsInJSON() {
        XCTAssert(self.testsDict.count == 10)
    }
    
    func test002_DecryptFromSingleRecipient_ShouldDecrypt() {
        let dict = self.testsDict["encrypt_single_recipient"] as! Dictionary<String, String>
        
        let privateKeyStr = dict["private_key"]!
        let privateKeyData = Data(base64Encoded: privateKeyStr)!
        
        let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
        
        let originalDataStr = dict["original_data"]!
        
        let cipherDataStr = dict["cipher_data"]!
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        let decryptedData = try! self.crypto.decrypt(cipherData, with: privateKey)
        let decryptedDataStr = decryptedData.base64EncodedString()
        
        XCTAssert(decryptedDataStr == originalDataStr)
    }
    
    func test003_DecryptFromMultipleRecipients_ShouldDecypt() {
        let dict = self.testsDict["encrypt_multiple_recipients"] as! Dictionary<String, Any>
        
        var privateKeys = Array<VirgilPrivateKey>()
        
        for privateKeyStr in dict["private_keys"] as! Array<String> {
            let privateKeyData = Data(base64Encoded: privateKeyStr)!
            
            let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
            
            privateKeys.append(privateKey)
        }
        
        XCTAssert(privateKeys.count > 0)
        
        let originalDataStr = dict["original_data"] as! String
        
        let cipherDataStr = dict["cipher_data"] as! String
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        for privateKey in privateKeys {
            let decryptedData = try! self.crypto.decrypt(cipherData, with: privateKey)
            let decrypteDataStr = decryptedData.base64EncodedString()
            
            XCTAssert(decrypteDataStr == originalDataStr)
        }
    }
    
    func test004_DecryptAndVerifySingleRecipient_ShouldDecryptAndVerify() {
        let dict = self.testsDict["sign_and_encrypt_single_recipient"] as! Dictionary<String, String>
        
        let privateKeyStr = dict["private_key"]!
        let privateKeyData = Data(base64Encoded: privateKeyStr)!
        
        let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
        
        let publicKey = try! self.crypto.extractPublicKey(from: privateKey)
        
        let originalDataStr = dict["original_data"]!
        let originalData = Data(base64Encoded: originalDataStr)!
        let originalStr = String(data: originalData, encoding: .utf8)!
        
        let cipherDataStr = dict["cipher_data"]!
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        let decryptedData = try! self.crypto.decryptAndVerify(cipherData, with: privateKey, using: publicKey)
        
        let decryptedStr = String(data: decryptedData, encoding: .utf8)!
        
        XCTAssert(originalStr == decryptedStr)
    }
    
    func test005_DecryptAndVerifyMultipleRecipients_ShouldDecryptAndVerify() {
        let dict = self.testsDict["sign_and_encrypt_multiple_recipients"] as! Dictionary<String, Any>
        
        var privateKeys = Array<VirgilPrivateKey>()
        
        for privateKeyStr in dict["private_keys"] as! Array<String> {
            let privateKeyData = Data(base64Encoded: privateKeyStr)!
            
            let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
            
            privateKeys.append(privateKey)
        }
        
        XCTAssert(privateKeys.count > 0)
        
        let originalDataStr = dict["original_data"] as! String
        
        let cipherDataStr = dict["cipher_data"] as! String
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        let signerPublicKey = try! self.crypto.extractPublicKey(from: privateKeys[0])
        
        for privateKey in privateKeys {
            let decryptedData = try! self.crypto.decryptAndVerify(cipherData, with: privateKey, using: signerPublicKey)
            let decrypteDataStr = decryptedData.base64EncodedString()
            
            XCTAssert(decrypteDataStr == originalDataStr)
        }
    }
    
    func test006_GenerateSignature_ShouldBeEqual() {
        let dict = self.testsDict["generate_signature"] as! Dictionary<String, String>
        
        let privateKeyStr = dict["private_key"]!
        let privateKeyData = Data(base64Encoded: privateKeyStr)!
        
        let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
        
        let originalDataStr = dict["original_data"]!
        let originalData = Data(base64Encoded: originalDataStr)!
        
        let signature = try! self.crypto.generateSignature(of: originalData, using: privateKey)
        let signatureStr = signature.base64EncodedString()
        
        let originalSignatureStr = dict["signature"]!
        let originalSignature = Data(base64Encoded: originalSignatureStr)!
        
        XCTAssert(try self.crypto.verifySignature(originalSignature, of: originalData, with: self.crypto.extractPublicKey(from: privateKey)) == true)
        
        XCTAssert(originalSignatureStr == signatureStr)
    }
    
    func test007_DecryptAndVerifyMultipleSigners_ShouldDecryptAndVerify() {
        let dict = self.testsDict["sign_and_encrypt_multiple_signers"] as! Dictionary<String, Any>
        
        let privateKeyStr = dict["private_key"] as! String
        let privateKeyData = Data(base64Encoded: privateKeyStr)!
        
        let privateKey = try! self.crypto.importPrivateKey(from: privateKeyData).privateKey
        
        var publicKeys = Array<VirgilPublicKey>()
        
        for publicKeyStr in dict["public_keys"] as! Array<String> {
            let publicKeyData = Data(base64Encoded: publicKeyStr)!
            
            let publicKey = try! self.crypto.importPublicKey(from: publicKeyData)
            
            publicKeys.append(publicKey)
        }
        
        let originalDataStr = dict["original_data"] as! String
        
        let cipherDataStr = dict["cipher_data"] as! String
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        let decryptedData = try! self.crypto.decryptAndVerify(cipherData, with: privateKey, usingOneOf: publicKeys)
        let decrypteDataStr = decryptedData.base64EncodedString()
        
        XCTAssert(decrypteDataStr == originalDataStr)
    }
    
    func test008_GenerateEd25519UsingSeed__ShouldMatch() {
        let dict = self.testsDict["generate_ed25519_using_seed"] as! Dictionary<String, Any>
        
        let seedStr = dict["seed"] as! String
        let seed = Data(base64Encoded: seedStr)!
        
        let keyPair = try! self.crypto.generateKeyPair(ofType: .ed25519, usingSeed: seed)
        
        let privateKeyStr = dict["private_key"] as! String
        let publicKeyStr = dict["public_key"] as! String
        let privateKeyData = Data(base64Encoded: privateKeyStr)!
        let publicKeyData = Data(base64Encoded: publicKeyStr)!

        XCTAssert(try! self.crypto.exportPrivateKey(keyPair.privateKey) == privateKeyData)
        XCTAssert(try! self.crypto.exportPublicKey(keyPair.publicKey) == publicKeyData)
    }
    
    func test009_AuthEncrypt__ShouldMatch() {
        let dict = self.testsDict["auth_encrypt"] as! Dictionary<String, Any>

        let privateKey1Str = dict["private_key1"] as! String
        let privateKey2Str = dict["private_key2"] as! String
        let publicKeyStr = dict["public_key"] as! String
        let dataSha512Str = dict["data_sha512"] as! String
        let cipherDataStr = dict["cipher_data"] as! String

        let privateKey1 = try! self.crypto.importPrivateKey(from: Data(base64Encoded: privateKey1Str)!).privateKey
        let keyPair2 = try! self.crypto.importPrivateKey(from: Data(base64Encoded: privateKey2Str)!)
        let publicKey = try! self.crypto.importPublicKey(from: Data(base64Encoded: publicKeyStr)!)
        let dataSha512 = Data(base64Encoded: dataSha512Str)!
        let cipherData = Data(base64Encoded: cipherDataStr)!
        
        let data = try! self.crypto.authDecrypt(cipherData, with: privateKey1, usingOneOf: [publicKey])

        XCTAssert(self.crypto.computeHash(for: data, using: .sha512) == dataSha512)

        do {
            _ = try self.crypto.authDecrypt(cipherData, with: keyPair2.privateKey, usingOneOf: [publicKey])
            XCTFail()
        }
        catch VirgilCryptoFoundation.FoundationError.errorKeyRecipientIsNotFound { }
        catch {
            XCTFail()
        }

        do {
            _ = try self.crypto.authDecrypt(cipherData, with: privateKey1, usingOneOf: [keyPair2.publicKey])
            XCTFail()
        }
        catch VirgilCryptoError.signerNotFound { }
        catch {
            XCTFail()
        }
    }
    
    func test010_AuthEncryptPQ__ShouldMatch() {
        let dict = self.testsDict["auth_encrypt_pq"] as! Dictionary<String, Any>

        let privateKeyStr = dict["private_key"] as! String
        let publicKeyStr = dict["public_key"] as! String
        let dataSha512Str = dict["data_sha512"] as! String
        let cipherDataStr = dict["cipher_data"] as! String

        let privateKey = try! self.crypto.importPrivateKey(from: Data(base64Encoded: privateKeyStr)!).privateKey
        let publicKey = try! self.crypto.importPublicKey(from: Data(base64Encoded: publicKeyStr)!)
        let dataSha512 = Data(base64Encoded: dataSha512Str)!
        let cipherData = Data(base64Encoded: cipherDataStr)!

        let data = try! self.crypto.authDecrypt(cipherData, with: privateKey, usingOneOf: [publicKey])

        XCTAssert(self.crypto.computeHash(for: data, using: .sha512) == dataSha512)
    }
    
    func test011_AuthEncryptPadding__ShouldMatch() {
        let dict = self.testsDict["auth_encrypt_padding"] as! Dictionary<String, Any>

        let privateKeyStr = dict["private_key"] as! String
        let publicKeyStr = dict["public_key"] as! String
        let dataSha512Str = dict["data_sha512"] as! String
        let cipherDataStr = dict["cipher_data"] as! String

        let privateKey = try! self.crypto.importPrivateKey(from: Data(base64Encoded: privateKeyStr)!).privateKey
        let publicKey = try! self.crypto.importPublicKey(from: Data(base64Encoded: publicKeyStr)!)
        let dataSha512 = Data(base64Encoded: dataSha512Str)!
        let cipherData = Data(base64Encoded: cipherDataStr)!

        let data = try! self.crypto.authDecrypt(cipherData, with: privateKey, usingOneOf: [publicKey])

        XCTAssert(self.crypto.computeHash(for: data, using: .sha512) == dataSha512)
    }
}
