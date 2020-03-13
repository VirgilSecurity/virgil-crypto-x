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

// MARK: - Extension for assymetric signing/verification
extension VirgilCrypto {
    /// Generates digital signature of data using private key
    ///
    /// - Note: Returned value contains only digital signature, not data itself.
    ///
    /// - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
    ///         It's secure to pass raw data here.
    ///
    /// - Note: Verification algorithm depends on PrivateKey type. Default: EdDSA for ed25519 key
    ///
    /// - Parameters:
    ///   - data: Data to sign
    ///   - privateKey: Private key used to generate signature
    /// - Returns: Digital signature
    /// - Throws: Rethrows from `Signer`
    @objc open func generateSignature(of data: Data, using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = Signer()

        signer.setRandom(random: self.rng)
        signer.setHash(hash: Sha512())

        signer.reset()
        signer.appendData(data: data)

        return try signer.sign(privateKey: privateKey.key)
    }

    /// Verifies digital signature of data
    ///
    /// - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - data: Data that was signed
    ///   - publicKey: Signer public key
    /// - Returns: True if signature is verified, false otherwise
    /// - Throws: Rethrows from `Verifier`
    @nonobjc open func verifySignature(_ signature: Data,
                                       of data: Data,
                                       with publicKey: VirgilPublicKey) throws -> Bool {
        let verifier = Verifier()

        try verifier.reset(signature: signature)

        verifier.appendData(data: data)

        return verifier.verify(publicKey: publicKey.key)
    }

    /// Verifies digital signature of data
    ///
    /// - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - data: signed Data
    ///   - publicKey: Signer public key
    /// - Returns: True if signature is verified, false otherwise
    @available(swift, obsoleted: 1.0)
    @objc open func verifySignature_objc(_ signature: Data, of data: Data, with publicKey: VirgilPublicKey) -> Bool {
        return (try? self.verifySignature(signature, of: data, with: publicKey)) ?? false
    }

    /// Generates digital signature of data stream using private key
    ///
    /// - Note: Returned value contains only digital signature, not data itself.
    ///
    /// - Note: Data inside this function is guaranteed to be hashed with SHA512 at least one time.
    ///         It's secure to pass raw data here.
    ///
    /// - Parameters:
    ///   - stream: Data stream to sign
    ///   - privateKey: Private key used to generate signature
    /// - Returns: Digital signature
    /// - Throws: Rethrows from `Signer`
    @objc open func generateStreamSignature(of stream: InputStream,
                                            using privateKey: VirgilPrivateKey) throws -> Data {
        let signer = Signer()

        signer.setRandom(random: self.rng)
        signer.setHash(hash: Sha512())

        signer.reset()

        try StreamUtils.forEachChunk(in: stream, streamSize: nil) {
            signer.appendData(data: $0)
        }

        return try signer.sign(privateKey: privateKey.key)
    }

    /// Verifies digital signature of data stream
    ///
    /// - Note: Verification algorithm depends on PublicKey type. Default: EdDSA
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - stream: Data stream that was signed
    ///   - publicKey: Signer public key
    /// - Returns: True if signature is verified, false otherwise
    /// - Throws: Rethrows from `Verifier`
    @nonobjc open func verifyStreamSignature(_ signature: Data,
                                             of stream: InputStream,
                                             with publicKey: VirgilPublicKey) throws -> Bool {
        let verifier = Verifier()

        try verifier.reset(signature: signature)

        try StreamUtils.forEachChunk(in: stream, streamSize: nil) {
            verifier.appendData(data: $0)
        }

        return verifier.verify(publicKey: publicKey.key)
    }

    /// Verifies digital signature of data
    ///
    /// - Note: Verification algorithm depends on PublicKey type. Default: EdDSA for ed25519 key
    ///
    /// - Parameters:
    ///   - signature: Digital signature
    ///   - stream: Stream that was signed
    ///   - publicKey: Signer public key
    /// - Returns: True if signature is verified, false otherwise
    @available(swift, obsoleted: 1.0)
    @objc open func verifyStreamSignature_objc(_ signature: Data,
                                               of stream: InputStream,
                                               with publicKey: VirgilPublicKey) -> Bool {
        return (try? self.verifyStreamSignature(signature, of: stream, with: publicKey)) ?? false
    }
}
