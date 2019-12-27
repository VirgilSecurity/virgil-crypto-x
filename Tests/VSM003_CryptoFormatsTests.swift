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

class VSM003_CryptoFormatsTests: XCTestCase {
    func test001_SignatureHash() {
        let crypto = try! VirgilCrypto()
        let keyPair = try! crypto.generateKeyPair()
        let signature = try! crypto.generateSignature(of: "test".data(using: .utf8)!, using: keyPair.privateKey)
        
        XCTAssert(signature.subdata(in: 0..<17) == Data(base64Encoded: "MFEwDQYJYIZIAWUDBAIDBQA="))
    }

    func test004_KeyIdentifierIsCorrect() {
        let crypto1 = try! VirgilCrypto()
        let keyPair1 = try! crypto1.generateKeyPair()
        
        XCTAssert(keyPair1.privateKey.identifier ==  keyPair1.publicKey.identifier)
        XCTAssert(crypto1.computeHash(for: try! crypto1.exportPublicKey(keyPair1.publicKey), using: .sha512).subdata(in: 0..<8) == keyPair1.privateKey.identifier)
        
        let crypto2 = try! VirgilCrypto(useSHA256Fingerprints: true)
        let keyPair2 = try! crypto2.generateKeyPair()
        
        XCTAssert(crypto1.computeHash(for: try! crypto1.exportPublicKey(keyPair2.publicKey), using: .sha256) == keyPair2.privateKey.identifier)
    }
    
    func test005_KeyPairTypeName() {
        let keyStr = KeyPairType.ed25519.getStringRepresentation()
        
        XCTAssert(keyStr == "ed25519")
        
        let keyType = try! KeyPairType(from: keyStr)
        
        XCTAssert(keyType == .ed25519)
    }
}
