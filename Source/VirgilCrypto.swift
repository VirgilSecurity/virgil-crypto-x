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
import VirgilCryptoAPI

/// Class for high level interactions with crypto library
@objc(VSMVirgilCrypto) open class VirgilCrypto: NSObject {
    @objc public let rng: Random
    @objc public let useSHA256Fingerprints: Bool

    @objc public init(useSHA256Fingerprints: Bool = false) throws {
        let rng = CtrDrbg()
        try rng.setupDefaults()

        self.rng = rng

        self.useSHA256Fingerprints = useSHA256Fingerprints

        super.init()
    }

    /// Computes hash
    ///
    /// - Parameters:
    ///   - data: Data to be hashed
    ///   - algorithm: Hash algorithm to use
    /// - Returns: Hash value
    @objc open func computeHash(for data: Data, using algorithm: HashAlgorithm = .sha512) -> Data {
        let hash: Hash

        switch algorithm {
        case .sha224:
            hash = Sha224()
        case .sha256:
            hash = Sha256()
        case .sha384:
            hash = Sha384()
        case .sha512:
            hash = Sha512()
        }

        return hash.hash(data: data)
    }
}
