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
@testable import VirgilCryptoApiImpl

class VSM004_CryptoBenchmarks: XCTestCase {
    private let crypto = VirgilCrypto()

    private let invocationCount: UInt64 = 1000

    private let toEncrypt = "this string will be encrypted".data(using: .utf8)!
    private let toSign = "this string will be signed".data(using: .utf8)!

    private func generateRandomData(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)

        guard status == errSecSuccess else {
            throw NSError(domain: "CryptoBenchmarks", code: -1, userInfo: nil)
        }

        return Data(bytes)
    }

    private func measure(title: String, maxTime: Int?, block: () -> Void) {
        var sum: UInt64 = 0

        print()
        print("Measurement of \(title)")

        for _ in 1...self.invocationCount {
            let start = DispatchTime.now()
            block()
            let end = DispatchTime.now()

            let elapsed = end.uptimeNanoseconds - start.uptimeNanoseconds

            sum += elapsed
        }

        let average = sum / self.invocationCount

        print("Average: \(average) ns")
        print()

        if let maxTime = maxTime {
            XCTAssert(maxTime > average)
        }
    }

    func test01_hash() {
        let data = try! self.generateRandomData(count: 8192)

        for algorithm: VSCHashAlgorithm in [.SHA512, .SHA256] {
            let block = {
                _ = self.crypto.computeHash(for: data, using: algorithm)
            }

            self.measure(title: "computation \(algorithm.rawStrValue)", maxTime: nil, block: block)
        }
    }

    func test02_encrypt() {
        for keyType: VSCKeyType in [.FAST_EC_ED25519, .EC_CURVE25519, .EC_SECP192R1, .RSA_4096] {
            let keyPair = try! self.crypto.generateKeyPair(ofType: keyType)

            let block = {
                _ = try! self.crypto.encrypt(self.toEncrypt, for: [keyPair.publicKey])
            }

            self.measure(title: "encryption with \(keyType.rawStrValue)", maxTime: nil, block: block)
        }
    }

    func test03_decrypt() {
        for keyType: VSCKeyType in [.FAST_EC_ED25519, .EC_CURVE25519, .EC_SECP192R1, .RSA_4096] {
            let keyPair = try! self.crypto.generateKeyPair(ofType: keyType)

            let encrypted = try! self.crypto.encrypt(self.toEncrypt, for: [keyPair.publicKey])

            let block = {
                _ = try! self.crypto.decrypt(encrypted, with: keyPair.privateKey)
            }

            self.measure(title: "decryption with \(keyType.rawStrValue)", maxTime: nil, block: block)
        }
    }

    func test04_sign() {
        for keyType: VSCKeyType in [.FAST_EC_ED25519, .EC_SECP192R1, .RSA_4096] {
            let keyPair = try! self.crypto.generateKeyPair()

            let block = {
                _ = try! self.crypto.generateSignature(of: self.toSign, using: keyPair.privateKey)
            }

            self.measure(title: "signing with \(keyType.rawStrValue)", maxTime: nil, block: block)
        }
    }

    func test05_verify() {
        for keyType: VSCKeyType in [.FAST_EC_ED25519, .EC_SECP192R1, .RSA_4096] {
            let keyPair = try! self.crypto.generateKeyPair()

            let signer = Signer(hash: kHashNameSHA384)
            let signature = try! signer.sign(self.toSign, privateKey: keyPair.privateKey.rawKey, keyPassword: nil)

            let block = {
                _ = self.crypto.verifySignature(signature, of: self.toSign, with: keyPair.publicKey)
            }

            self.measure(title: "verifying with \(keyType.rawStrValue)", maxTime: nil, block: block)
        }
    }
}

extension VSCHashAlgorithm {
    var rawStrValue: String {
        switch self {
        case .SHA256:
            return "SHA256"
        case .SHA512:
            return "SHA512"
        default:
            return "Unknown hash algorithm"
        }
    }
}

extension VSCKeyType {
    var rawStrValue: String {
        switch self {
        case .FAST_EC_ED25519:
            return "ED25519"
        case .EC_CURVE25519:
            return "CURVE25519"
        case .EC_SECP192R1:
            return "SECP192R1"
        case .RSA_4096:
            return "RSA_4096"
        default:
            return "Unknown key type"
        }
    }
}
