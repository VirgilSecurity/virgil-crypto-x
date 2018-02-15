//
//  VirgilCrypto.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/18/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCrypto
import VirgilCryptoAPI

@objc(VSMVirgilCrypto) public class VirgilCrypto: NSObject {
    @objc public static let CustomParamKeySignature = "VIRGIL-DATA-SIGNATURE"
    @objc public static let CustomParamKeySignerId = "VIRGIL-DATA-SIGNER-ID"

    @objc public let defaultKeyType: VSCKeyType
    @objc public let useSHA256Fingerprints: Bool

    @objc public init(defaultKeyType: VSCKeyType = .FAST_EC_ED25519, useSHA256Fingerprints: Bool = false) {
        self.defaultKeyType = defaultKeyType
        self.useSHA256Fingerprints = useSHA256Fingerprints

        super.init()
    }

    @objc public func encrypt(_ data: Data, for recipients: [VirgilPublicKey]) throws -> Data {
        let cipher = Cipher()

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        let encryptedData = try cipher.encryptData(data, embedContentInfo: true)

        return encryptedData
    }

    @objc public func encrypt(_ stream: InputStream, to outputStream: OutputStream,
                              for recipients: [VirgilPublicKey]) throws {
        let cipher = ChunkCipher()

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        try cipher.encryptData(from: stream, to: outputStream)
    }

    @objc public func verifySignature(_ signature: Data, of data: Data, with publicKey: VirgilPublicKey) -> Bool {
        let signer = Signer()

        do {
            try signer.verifySignature(signature, data: data, publicKey: publicKey.rawKey)
        }
        catch {
            return false
        }

        return true
    }

    @objc public func verifyStreamSignature(_ signature: Data, of stream: InputStream,
                                            with publicKey: VirgilPublicKey) -> Bool {
        let signer = StreamSigner()

        do {
            try signer.verifySignature(signature, from: stream, publicKey: publicKey.rawKey)
        }
        catch {
            return false
        }

        return true
    }

    @objc public func decrypt(_ data: Data, with privateKey: VirgilPrivateKey) throws -> Data {
        let cipher = Cipher()

        return try cipher.decryptData(data, recipientId: privateKey.identifier,
                                      privateKey: privateKey.rawKey, keyPassword: nil)
    }

    @objc public func decrypt(_ stream: InputStream, to outputStream: OutputStream,
                              with privateKey: VirgilPrivateKey) throws {
        let cipher = ChunkCipher()

        try cipher.decrypt(from: stream, to: outputStream, recipientId: privateKey.identifier,
                           privateKey: privateKey.rawKey, keyPassword: nil)
    }

    @objc public func signThenEncrypt(_ data: Data, with privateKey: VirgilPrivateKey,
                                      for recipients: [VirgilPublicKey]) throws -> Data {
        let signer = Signer(hash: kHashNameSHA512)

        let signature = try signer.sign(data, privateKey: privateKey.rawKey, keyPassword: nil)

        let cipher = Cipher()

        try cipher.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)

        let publicKey = try self.extractPublicKey(from: privateKey)

        let signerId = publicKey.identifier

        try cipher.setData(signerId, forKey: VirgilCrypto.CustomParamKeySignerId)

        try recipients.forEach {
            try cipher.addKeyRecipient($0.identifier, publicKey: $0.rawKey)
        }

        return try cipher.encryptData(data, embedContentInfo: true)
    }

    @objc public func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey,
                                        using signerPublicKey: VirgilPublicKey) throws -> Data {
        let cipher = Cipher()

        let decryptedData = try cipher.decryptData(data, recipientId: privateKey.identifier,
                                                   privateKey: privateKey.rawKey, keyPassword: nil)
        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)

        let signer = Signer()
        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.rawKey)

        return decryptedData
    }

    @objc public func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey,
                                        usingOneOf signersPublicKeys: [VirgilPublicKey]) throws -> Data {
        let cipher = Cipher()

        let decryptedData = try cipher.decryptData(data, recipientId: privateKey.identifier,
                                                   privateKey: privateKey.rawKey, keyPassword: nil)

        let signature = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignature)
        let signerId = try cipher.data(forKey: VirgilCrypto.CustomParamKeySignerId)

        guard let signerPublicKey = signersPublicKeys.first(where: { $0.identifier == signerId }) else {
            throw VirgilCryptoError.signerNotFound
        }

        let signer = Signer()
        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.rawKey)

        return decryptedData
    }

    @objc public func generateSignature(of data: Data, using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = Signer(hash: kHashNameSHA512)

        return try signer.sign(data, privateKey: privateKey.rawKey, keyPassword: nil)
    }

    @objc public func generateStreamSignature(of stream: InputStream,
                                              using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = StreamSigner(hash: kHashNameSHA512)

        let signature = try signer.signStreamData(stream, privateKey: privateKey.rawKey, keyPassword: nil)

        return signature
    }

    @objc public func computeHash(for data: Data, using algorithm: VSCHashAlgorithm) -> Data {
        let hash = Hash(algorithm: algorithm)

        return hash.hash(data)
    }
}
