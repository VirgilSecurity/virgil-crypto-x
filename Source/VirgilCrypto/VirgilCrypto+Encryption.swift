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

import VirgilCryptoFoundation

// MARK: - Extension for assymetric encryption/decryption
extension VirgilCrypto {
    /// Encrypts data for passed PublicKeys
    ///
    /// 1. Generates random AES-256 KEY1
    /// 2. Encrypts data with KEY1 using AES-256-GCM
    /// 3. Generates ephemeral key pair for each recipient
    /// 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 5. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - data: Data to be encrypted
    ///   - recipients: Public Keys of recipients
    ///   - enablePadding: If true, will add padding to plain text before encryption.
    ///                    This is recommended for data for which exposing length can
    ///                    cause security issues (e.g. text messages)
    /// - Returns: Encrypted data
    /// - Throws: Rethrows from `RecipientCipher`
    @objc open func encrypt(_ data: Data,
                            for recipients: [VirgilPublicKey],
                            enablePadding: Bool = false) throws -> Data {
        return try self.encrypt(inputOutput: .data(input: data),
                                signingOptions: nil,
                                recipients: recipients,
                                enablePadding: enablePadding)!
    }

    /// Decrypts data using passed PrivateKey
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data using KEY1 and AES-256-GCM
    ///
    /// - Parameters:
    ///   - data: Encrypted data
    ///   - privateKey: Recipient's private key
    /// - Returns: Decrypted data
    /// - Throws: Rethrows from `RecipientCipher`
    @objc open func decrypt(_ data: Data, with privateKey: VirgilPrivateKey) throws -> Data {
        return try self.decrypt(inputOutput: .data(input: data), verifyingOptions: nil, privateKey: privateKey)!
    }

    /// Encrypts data stream for passed PublicKeys
    ///
    /// 1. Generates random AES-256 KEY1
    /// 2. Encrypts data with KEY1 using AES-256-GCM
    /// 3. Generates ephemeral key pair for each recipient
    /// 4. Uses Diffie-Hellman to obtain shared secret with each recipient's public key & each ephemeral private key
    /// 5. Computes KDF to obtain AES-256 key from shared secret for each recipient
    /// 6. Encrypts KEY1 with this key using AES-256-CBC for each recipient
    ///
    /// - Parameters:
    ///   - stream: data Stream to be encrypted
    ///   - outputStream: Stream with encrypted data
    ///   - recipients: Recipients
    ///   - enablePadding: If true, will add padding to plain text before encryption.
    ///                    This is recommended for data for which exposing length can
    ///                    cause security issues (e.g. text messages)
    /// - Throws: Rethrows from `RecipientCipher`
    @objc open func encrypt(_ stream: InputStream, to outputStream: OutputStream,
                            for recipients: [VirgilPublicKey], enablePadding: Bool = false) throws {
        _ = try self.encrypt(inputOutput: .stream(input: stream, streamSize: nil, output: outputStream),
                             signingOptions: nil,
                             recipients: recipients,
                             enablePadding: enablePadding)
    }

    /// Decrypts data stream using passed PrivateKey
    ///
    /// - Note: Decrypted stream should not be used until decryption
    ///         of whole InputStream completed due to security reasons
    ///
    /// 1. Uses Diffie-Hellman to obtain shared secret with sender ephemeral public key & recipient's private key
    /// 2. Computes KDF to obtain AES-256 KEY2 from shared secret
    /// 3. Decrypts KEY1 using AES-256-CBC
    /// 4. Decrypts data using KEY1 and AES-256-GCM
    ///
    /// - Parameters:
    ///   - stream: Stream with encrypted data
    ///   - outputStream: Stream with decrypted data
    ///   - privateKey: Recipient's private key
    /// - Throws: Rethrows from `RecipientCipher`
    @objc open func decrypt(_ stream: InputStream, to outputStream: OutputStream,
                            with privateKey: VirgilPrivateKey) throws {
        _ = try self.decrypt(inputOutput: .stream(input: stream, streamSize: nil, output: outputStream),
                             verifyingOptions: nil,
                             privateKey: privateKey)
    }
}
