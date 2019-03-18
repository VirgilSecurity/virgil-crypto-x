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

/// MARK: - Extension for assymetric encryption/decryption
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
    /// - Returns: Encrypted data
    /// - Throws: Rethrows from RecipientCipher
    @objc open func encrypt(_ data: Data, for recipients: [VirgilPublicKey]) throws -> Data {
        let aesGcm = Aes256Gcm()
        let cipher = RecipientCipher()

        cipher.setEncryptionCipher(encryptionCipher: aesGcm)
        cipher.setRandom(random: self.rng)

        recipients.forEach {
            cipher.addKeyRecipient(recipientId: $0.identifier, publicKey: $0.publicKey)
        }

        try cipher.startEncryption()

        var result = cipher.packMessageInfo()

        result += try cipher.processEncryption(data: data)

        result += try cipher.finishEncryption()

        return result
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
    /// - Throws: Rethrows from RecipientCipher
    @objc open func decrypt(_ data: Data, with privateKey: VirgilPrivateKey) throws -> Data {
        let cipher = RecipientCipher()

        try cipher.startDecryptionWithKey(recipientId: privateKey.identifier,
                                          privateKey: privateKey.privateKey,
                                          messageInfo: Data())

        var result = Data()

        result += try cipher.processDecryption(data: data)

        result += try cipher.finishDecryption()

        return result
    }

}
