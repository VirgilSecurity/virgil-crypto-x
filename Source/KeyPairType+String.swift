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

// MARK: - String representation extension
extension KeyPairType {
    // Raw value of this enum equals to enum case name itself
    internal enum KeyPairTypeStr: String {
        case ed25519
        case curve25519
        case secp256r1
        case rsa2048
        case rsa4096
        case rsa8192
        case curve25519Round5
        case curve25519Round5Ed25519Falcon
        case curve25519Ed25519
    }

    /// Initializer key pair type from string representation
    /// - Parameter stringRepresentation: string representation
    /// - Throws: VirgilCryptoError.unknownKeyType if key type is unknown
    public init(from stringRepresentation: String) throws {
        switch stringRepresentation {
        case KeyPairTypeStr.ed25519.rawValue:
            self = .ed25519
        case KeyPairTypeStr.curve25519.rawValue:
            self = .curve25519
        case KeyPairTypeStr.secp256r1.rawValue:
            self = .secp256r1
        case KeyPairTypeStr.rsa2048.rawValue:
            self = .rsa2048
        case KeyPairTypeStr.rsa4096.rawValue:
            self = .rsa4096
        case KeyPairTypeStr.rsa8192.rawValue:
            self = .rsa8192
        case KeyPairTypeStr.curve25519Round5.rawValue:
            self = .curve25519Round5
        case KeyPairTypeStr.curve25519Round5Ed25519Falcon.rawValue:
            self = .curve25519Round5Ed25519Falcon
        case KeyPairTypeStr.curve25519Ed25519.rawValue:
            self = .curve25519Ed25519

        default:
            throw VirgilCryptoError.unknownKeyType
        }
    }

    /// Returns string representation for key type
    public func getStringRepresentation() -> String {
        switch self {
        case .ed25519:
            return KeyPairTypeStr.ed25519.rawValue
        case .curve25519:
            return KeyPairTypeStr.curve25519.rawValue
        case .secp256r1:
            return KeyPairTypeStr.secp256r1.rawValue
        case .rsa2048:
            return KeyPairTypeStr.rsa2048.rawValue
        case .rsa4096:
            return KeyPairTypeStr.rsa4096.rawValue
        case .rsa8192:
            return KeyPairTypeStr.rsa8192.rawValue
        case .curve25519Round5:
            return KeyPairTypeStr.curve25519Round5.rawValue
        case .curve25519Round5Ed25519Falcon:
            return KeyPairTypeStr.curve25519Round5Ed25519Falcon.rawValue
        case .curve25519Ed25519:
            return KeyPairTypeStr.curve25519Ed25519.rawValue
        }
    }
}
