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

class VSM004_CryptoBenchmarks: XCTestCase {
    private let crypto = try! VirgilCrypto()

    private let invocationCount: UInt64 = 10

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

    private func measure(title: String, maxTime: Int, block: () -> Void) {
        var sum: UInt64 = 0

        print()
        print("Measurement of \(title)")

        for i in 1...self.invocationCount {
            let start = DispatchTime.now()
            block()
            let end = DispatchTime.now()

            let elapsed = end.uptimeNanoseconds - start.uptimeNanoseconds

            sum += elapsed
            print("\(i) atempt: \(elapsed) ns")
        }

        let average = sum / self.invocationCount

        print("Avarage: \(average) ns")
        print()

        XCTAssert(maxTime > average)
    }

    func test01_hash() {
        let data = try! self.generateRandomData(count: 8192)

        for algorithm: HashAlgorithm in [.sha512, .sha256] {
            let block = {
                _ = self.crypto.computeHash(for: data, using: algorithm)
            }

            self.measure(title: "computation \(algorithm.rawStrValue)", maxTime: 1_000_000, block: block)
        }
    }

    func test02_encrypt() {
        for keyType: KeyPairType in [.ed25519, .curve25519, .secp256r1, .rsa4096] {
            let keyPair = try! self.crypto.generateKeyPair(ofType: keyType)

            let block = {
                _ = try! self.crypto.encrypt(self.toEncrypt, for: [keyPair.publicKey])
            }

            self.measure(title: "encryption with \(keyType.rawStrValue)", maxTime: 10_000_000, block: block)
        }
    }

    func test03_decrypt() {
        for keyType: KeyPairType in [.ed25519, .curve25519, .secp256r1, .rsa4096] {
            let keyPair = try! self.crypto.generateKeyPair(ofType: keyType)

            let encrypted = try! self.crypto.encrypt(self.toEncrypt, for: [keyPair.publicKey])

            let block = {
                _ = try! self.crypto.decrypt(encrypted, with: keyPair.privateKey)
            }

            self.measure(title: "decryption with \(keyType.rawStrValue)", maxTime: 100_000_000, block: block)
        }
    }

    func test04_sign() {
        for keyType: KeyPairType in [.ed25519, .secp256r1, .rsa4096] {
            let keyPair = try! self.crypto.generateKeyPair()

            let block = {
                _ = try! self.crypto.generateSignature(of: self.toSign, using: keyPair.privateKey)
            }

            self.measure(title: "signing with \(keyType.rawStrValue)", maxTime: 1_000_000, block: block)
        }
    }

    func test05_verify() {
        for keyType: KeyPairType in [.ed25519, .secp256r1, .rsa4096] {
            let keyPair = try! self.crypto.generateKeyPair()

            let signature = try! self.crypto.generateSignature(of: self.toSign, using: keyPair.privateKey)

            let block = {
                _ = try! self.crypto.verifySignature(signature, of: self.toSign, with: keyPair.publicKey)
            }

            self.measure(title: "verifying with \(keyType.rawStrValue)", maxTime: 10_000_000, block: block)
        }
    }
}

private extension HashAlgorithm {
    var rawStrValue: String {
        switch self {
        case .sha224:
            return "sha224"
        case .sha256:
            return "sha256"
        case .sha384:
            return "sha384"
        case .sha512:
            return "sha512"
        }
    }
}

private extension KeyPairType {
    var rawStrValue: String {
        switch self {
        case .curve25519:
            return "curve25519"
        case .ed25519:
            return "ed25519"
        case .rsa2048:
            return "rsa2048"
        case .rsa4096:
            return "rsa4096"
        case .rsa8192:
            return "rsa8192"
        case .secp256r1:
            return "secp256r1"
        }
    }
}
