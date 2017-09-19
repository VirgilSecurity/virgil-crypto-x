//
//  VirgilCrypto.swift
//  VirgilCrypto
//
//  Created by Oleksandr Deundiak on 9/18/17.
//  Copyright © 2017 VirgilSecurity. All rights reserved.
//

import Foundation
import VirgilCryptoAPI

@objc(VSCVirgilCrypto) public class VirgilCrypto: NSObject {
    public static let CustomParamKeySignature = "VIRGIL-DATA-SIGNATURE"
    public static let CustomParamKeySignerId = "VIRGIL-DATA-SIGNER-ID"
    
    let defaultKeyType: VSCKeyType
    public init(defaultKeyType: VSCKeyType) {
        self.defaultKeyType = defaultKeyType
        
        super.init()
    }
    
    public override convenience init() {
        self.init(defaultKeyType: .FAST_EC_ED25519)
    }

    public func encrypt(data: Data, for recipients: [VirgilPublicKey]) throws -> Data {
        let cryptor = VSCCryptor()
        
        try recipients.forEach(){
            try cryptor.addKeyRecipient($0.key, publicKey: $0.key)
        }
        
        let encryptedData = try cryptor.encryptData(data, embedContentInfo: true)
        
        return encryptedData
    }
    
    public func encrypt(stream: InputStream, to outputStream: OutputStream, for recipients: [VirgilPublicKey]) throws {
        let cryptor = VSCChunkCryptor()
        
        try recipients.forEach(){
            try cryptor.addKeyRecipient($0.key, publicKey: $0.key)
        }
        
        try cryptor.encryptData(from: stream, to: outputStream)
    }
    
    public func verifySignature(_ signature: Data, of data: Data, withVirgil publicKey: VirgilPublicKey) throws {
        let signer = VSCSigner()
        
        try signer.verifySignature(signature, data: data, publicKey: publicKey.key)
    }
    
    public func verifyStreamSignature(_ signature: Data, of stream: InputStream, with publicKey: VirgilPublicKey) throws {
        let signer = VSCStreamSigner()
        
        try signer.verifySignature(signature, from: stream, publicKey: publicKey.key)
    }
    
    public func decrypt(data: Data, with privateKey: VirgilPrivateKey) throws -> Data {
        let cryptor = VSCCryptor()
        
        return try cryptor.decryptData(data, recipientId: privateKey.identifier, privateKey: privateKey.key, keyPassword: nil)
    }
    
    public func decrypt(stream: InputStream, to outputStream: OutputStream, with privateKey: VirgilPrivateKey) throws {
        let cryptor = VSCChunkCryptor()
        
        try cryptor.decrypt(from: stream, to: outputStream, recipientId: privateKey.identifier, privateKey: privateKey.key, keyPassword: nil)
    }
    
    public func signThenEncrypt(_ data: Data, with privateKey: VirgilPrivateKey, for recipients: [VirgilPublicKey]) throws -> Data {
        let signer = VSCSigner()
        
        let signature = try signer.sign(data, privateKey: privateKey.key, keyPassword: nil)
        
        let cryptor = VSCCryptor()
        
        try cryptor.setData(signature, forKey: VirgilCrypto.CustomParamKeySignature)
        
        let publicKey = try self.extractPublicKey(from: privateKey)
        
        let signerId = publicKey.identifier
        
        try cryptor.setData(signerId, forKey: VirgilCrypto.CustomParamKeySignerId)
        
        try recipients.forEach(){
            try cryptor.addKeyRecipient($0.identifier, publicKey: $0.key)
        }
        
        return try cryptor.encryptData(data, embedContentInfo: true)
    }
    
    public func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey, using signerPublicKey: VirgilPublicKey) throws -> Data {
        let cryptor = VSCCryptor()
        
        let decryptedData = try cryptor.decryptData(data, recipientId: privateKey.identifier, privateKey: privateKey.key, keyPassword: nil)
        let signature = try cryptor.data(forKey: VirgilCrypto.CustomParamKeySignature)
        
        let signer = VSCSigner()
        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.key)
        
        return decryptedData
    }
    
    public func decryptThenVerify(_ data: Data, with privateKey: VirgilPrivateKey, usingOneOf signersPublicKeys: [VirgilPublicKey]) throws -> Data {
        let cryptor = VSCCryptor()
        
        let decryptedData = try cryptor.decryptData(data, recipientId: privateKey.identifier, privateKey: privateKey.key, keyPassword: nil)
        
        let signature = try cryptor.data(forKey: VirgilCrypto.CustomParamKeySignature)
        let signerId = try cryptor.data(forKey: VirgilCrypto.CustomParamKeySignerId)
        
        guard let signerPublicKey = signersPublicKeys.first(where: { $0.identifier == signerId }) else {
            throw NSError()
        }
        
        let signer = VSCSigner()
        try signer.verifySignature(signature, data: decryptedData, publicKey: signerPublicKey.key)
        
        return decryptedData
    }
    
    public func generateSignature(of data: Data, usingVirgil privateKey: VirgilPrivateKey) throws -> Data {
        let signer = VSCSigner()
        
        return try signer.sign(data, privateKey: privateKey.key, keyPassword: nil)
    }
    
    public func generateStreamSignature(of stream: InputStream, using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = VSCStreamSigner()
        
        let signature = try signer.signStreamData(stream, privateKey: privateKey.key, keyPassword: nil)
        
        return signature
    }
    
    public func computeHash(for data: Data, using algorithm: VSCHashAlgorithm) -> Data {
        let hash = VSCHash(algorithm: algorithm)!
        
        return hash.hash(data)!
    }
}
