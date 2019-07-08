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

/// Errors for this framework
///
/// - signerNotFound: signer not found
/// - signatureNotFound: signature not found
/// - signatureNotVerified: signature not verified
/// - unknownAlgId: unknown alg id
/// - rsaShouldBeConstructedDirectly: rsa should be constructed directly
/// - unsupportedRsaLength: unsupported rsa length
/// - keyDoesntSupportSigning: key doesn't support signing
/// - passedKeyIsNotVirgil: passed key is not virgil
/// - outputStreamError: output stream has no space left
/// - inputStreamError: input stream has no space left
/// - invalidSeedSize: invalid seed size
@objc(VSMVirgilCryptoError) public enum VirgilCryptoError: Int, LocalizedError {
    case signerNotFound = 1
    case signatureNotFound = 2
    case signatureNotVerified = 3
    case unknownAlgId = 4
    case rsaShouldBeConstructedDirectly = 5
    case unsupportedRsaLength = 6
    case keyDoesntSupportSigning = 7
    case passedKeyIsNotVirgil = 8
    case outputStreamError = 9
    case inputStreamError = 10
    case invalidSeedSize = 11

    /// Human-readable localized description
    public var errorDescription: String? {
        switch self {
        case .signerNotFound:
            return "Signer not found"
        case .signatureNotFound:
            return "Signature not found"
        case .signatureNotVerified:
            return "Signature not verified"
        case .unknownAlgId:
            return "Unknown alg id"
        case .rsaShouldBeConstructedDirectly:
            return "rsa should be constructed directly"
        case .unsupportedRsaLength:
            return "Unsupported rsa length"
        case .keyDoesntSupportSigning:
            return "Key doesn't support signing"
        case .passedKeyIsNotVirgil:
            return "Passed key is not virgil"
        case .outputStreamError:
            return "Output stream has no space left"
        case .inputStreamError:
            return "Input stream has no space left"
        case .invalidSeedSize:
            return "Invalid seed size"
        }
    }
}
