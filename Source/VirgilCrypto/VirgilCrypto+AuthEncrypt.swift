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

import Foundation
import VirgilCryptoFoundation

extension VirgilCrypto {
    /// Signs (with private key) Then Encrypts data (and signature) for passed PublicKeys
    ///
    /// 1. Generates signature depending on KeyType
    /// 2. Generates random AES-256 KEY1
    /// 3. Encrypts data with KEY1 using AES-256-GCM and generates signature
    /// 4. Encrypts signature with KEY1 using AES-256-GCM
    /// 5. Generates ephemeral key pair for each recipient
    /// 6. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 7. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 8. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - data: Data to be signedThenEncrypted
    ///   - privateKey: Sender private key
    ///   - recipients: Recipients' public keys
    ///   - enablePadding: If true, will add padding to plain text before encryption.
    ///                    This is recommended for data for which exposing length can
    ///                    cause security issues (e.g. text messages)
    /// - Returns: SignedThenEncrypted data
    /// - Throws: Rethrows from `RecipientCipher`.
    @objc open func authEncrypt(_ data: Data, with privateKey: VirgilPrivateKey,
                                for recipients: [VirgilPublicKey], enablePadding: Bool = true) throws -> Data {
        return try self.encrypt(inputOutput: .data(input: data),
                                signingOptions: SigningOptions(privateKey: privateKey, mode: .signThenEncrypt),
                                recipients: recipients,
                                enablePadding: enablePadding)!
    }

    /// Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data and signature using KEY1 and AES-256-GCM
    /// 5. Finds corresponding PublicKey according to signer id inside data
    /// 6. Verifies signature
    ///
    /// - Parameters:
    ///   - data: Signed Then Encrypted data
    ///   - privateKey: Receiver's private key
    ///   - signersPublicKeys: Array of possible signers public keys.
    ///                        WARNING: Data should have signature of ANY public key from array.
    /// - Returns: DecryptedThenVerified data
    /// - Throws: Rethrows from `RecipientCipher`.
    @objc open func authDecrypt(_ data: Data, with privateKey: VirgilPrivateKey,
                                usingOneOf signersPublicKeys: [VirgilPublicKey]) throws -> Data {
        return try self.authDecrypt(data,
                                    with: privateKey,
                                    usingOneOf: signersPublicKeys,
                                    allowNotEncryptedSignature: false)
    }

    /// Decrypts (with private key) data and signature and Verifies signature using any of signers' PublicKeys
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data and signature using KEY1 and AES-256-GCM
    /// 5. Finds corresponding PublicKey according to signer id inside data
    /// 6. Verifies signature
    ///
    /// - Parameters:
    ///   - data: Signed Then Encrypted data
    ///   - privateKey: Receiver's private key
    ///   - signersPublicKeys: Array of possible signers public keys.
    ///                        WARNING: Data should have signature of ANY public key from array.
    ///   - allowNotEncryptedSignature: Allows storing signature in plain text
    ///                                 for compatibility with deprecated signAndEncrypt
    /// - Returns: DecryptedThenVerified data
    /// - Throws: Rethrows from `RecipientCipher`.
    @objc open func authDecrypt(_ data: Data, with privateKey: VirgilPrivateKey,
                                usingOneOf signersPublicKeys: [VirgilPublicKey],
                                allowNotEncryptedSignature: Bool) throws -> Data {
        let verifyMode: VerifyingMode = allowNotEncryptedSignature ? .any : .decryptThenVerify
        return try self.decrypt(inputOutput: .data(input: data),
                                verifyingOptions: VerifyingOptions(publicKeys: signersPublicKeys,
                                                                   mode: verifyMode),
                                privateKey: privateKey)!
    }

    /// Signs (with private key) Then Encrypts stream (and signature) for passed PublicKeys
    ///
    /// 1. Generates signature depending on KeyType
    /// 2. Generates random AES-256 KEY1
    /// 3. Encrypts data with KEY1 using AES-256-GCM and generates signature
    /// 4. Encrypts signature with KEY1 using AES-256-GCM
    /// 5. Generates ephemeral key pair for each recipient
    /// 6. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 7. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 8. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    /// 
    /// - Parameters:
    ///   - stream: Input stream
    ///   - streamSize: Input stream size
    ///   - outputStream: Output stream
    ///   - privateKey: Private key to generate signatures
    ///   - recipients: Recipients public keys
    ///   - enablePadding: If true, will add padding to plain text before encryption.
    ///                    This is recommended for data for which exposing length can
    ///                    cause security issues (e.g. text messages)
    /// - Throws: Rethrows from `RecipientCipher`.
    @objc open func authEncrypt(_ stream: InputStream,
                                streamSize: Int,
                                to outputStream: OutputStream,
                                with privateKey: VirgilPrivateKey,
                                for recipients: [VirgilPublicKey],
                                enablePadding: Bool = false) throws {
        _ = try self.encrypt(inputOutput: .stream(input: stream, streamSize: streamSize, output: outputStream),
                             signingOptions: SigningOptions(privateKey: privateKey, mode: .signThenEncrypt),
                             recipients: recipients,
                             enablePadding: enablePadding)
    }

    /// Decrypts (using passed PrivateKey) then verifies (using one of public keys) stream
    ///
    /// - Note: Decrypted stream should not be used until decryption
    ///         of whole InputStream completed due to security reasons
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data and signature using KEY1 and AES-256-GCM
    /// 5. Finds corresponding PublicKey according to signer id inside data
    /// 6. Verifies signature
    ///
    /// - Parameters:
    ///   - stream: Stream with encrypted data
    ///   - outputStream: Stream with decrypted data
    ///   - privateKey: Recipient's private key
    ///   - signersPublicKeys: Array of possible signers public keys.
    ///                        WARNING: Stream should have signature of ANY public key from array.
    /// - Throws: Rethrows from `RecipientCipher`.
    @objc open func authDecrypt(_ stream: InputStream, to outputStream: OutputStream,
                                with privateKey: VirgilPrivateKey,
                                usingOneOf signersPublicKeys: [VirgilPublicKey]) throws {
        _ = try self.decrypt(inputOutput: .stream(input: stream, streamSize: nil, output: outputStream),
                             verifyingOptions: VerifyingOptions(publicKeys: signersPublicKeys,
                                                                mode: .decryptThenVerify),
                             privateKey: privateKey)
    }
}
