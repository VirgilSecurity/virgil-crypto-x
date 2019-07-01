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
import VSCCrypto

// swiftlint:disable force_unwrapping

/// Declares error types and codes
///
/// - underlyingCryptoError: Crypto library returned error
@objc(VSCVirgilPythiaError) public enum VirgilPythiaError: Int, Error {
    case underlyingCryptoError = 0
}

/// Class with Pythia-related crypto operations
@objc(VSCVirgilPythia) public class VirgilPythia: NSObject {
    private static func trim(data: inout Data, from buf: UnsafeMutablePointer<pythia_buf_t>) {
        data.removeLast(data.count - buf.pointee.len)
    }

    /// Blinds password.
    ///
    /// Turns password into a pseudo-random string.
    /// This step is necessary to prevent 3rd-parties from knowledge of end user's password.
    ///
    /// - Parameter password: end user's password.
    /// - Returns: BlindResult with blinded password and blinding secret
    /// - Throws: VirgilPythiaError.underlyingCryptoError
    @objc public func blind(password: Data) throws -> BlindResult {
        let blindedPasswordCount = PYTHIA_G1_BUF_SIZE
        var blindedPassword = Data(count: blindedPasswordCount)
        let blindedPasswordBuf = pythia_buf_new()!

        let blindingSecretCount = PYTHIA_BN_BUF_SIZE
        var blindingSecret = Data(count: blindingSecretCount)
        let blindingSecretBuf = pythia_buf_new()!

        let passwordBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(blindingSecretBuf)
            pythia_buf_free(passwordBuf)
        }

        let proxyResult = password.withUnsafeBytes { (passwordPointer: UnsafePointer<UInt8>) -> Int32 in

            blindedPassword.withUnsafeMutableBytes { (blindedPasswordPointer: UnsafeMutablePointer<UInt8>) -> Int32 in
                blindingSecret.withUnsafeMutableBytes { (blindingSecretPointer: UnsafeMutablePointer<UInt8>) -> Int32 in

                    pythia_buf_setup(blindedPasswordBuf, blindedPasswordPointer, blindedPasswordCount, 0)
                    pythia_buf_setup(blindingSecretBuf, blindingSecretPointer, blindingSecretCount, 0)

                    let passwordMutable = UnsafeMutablePointer(mutating: passwordPointer)
                    pythia_buf_setup(passwordBuf, passwordMutable, 0, password.count)

                    return virgil_pythia_blind(passwordBuf, blindedPasswordBuf, blindingSecretBuf)

                }
            }
        }

        guard proxyResult == 0 else {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &blindedPassword, from: blindedPasswordBuf)
        VirgilPythia.trim(data: &blindingSecret, from: blindingSecretBuf)

        return BlindResult(blindedPassword: blindedPassword, blindingSecret: blindingSecret)
    }

    /// Deblinds transformed password value using previously returned blinding_secret from blind operation.
    ///
    /// - Parameters:
    ///   - transformedPassword: GT transformed password from transform operation
    ///   - blindingSecret: BN value that was generated during blind operation
    /// - Returns: GT deblinded transformed password
    /// - Throws: VirgilPythiaError.underlyingCryptoError
    @objc public func deblind(transformedPassword: Data, blindingSecret: Data) throws -> Data {
        let deblindedPasswordCount = PYTHIA_GT_BUF_SIZE
        var deblindedPassword = Data(count: deblindedPasswordCount)
        let deblindedPasswordBuf = pythia_buf_new()!

        let transformedPasswordBuf = pythia_buf_new()!
        let blindingSecretBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(deblindedPasswordBuf)
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindingSecretBuf)
        }

        let proxyResult = transformedPassword.withUnsafeBytes { (transformedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
            blindingSecret.withUnsafeBytes { (blindingSecretPointer: UnsafePointer<UInt8>) -> Int32 in

                deblindedPassword.withUnsafeMutableBytes { (deblindedPasswordPointer: UnsafeMutablePointer<UInt8>) -> Int32 in

                    pythia_buf_setup(deblindedPasswordBuf, deblindedPasswordPointer, deblindedPasswordCount, 0)

                    let transformedPasswordMutable = UnsafeMutablePointer(mutating: transformedPasswordPointer)
                    let blindingSecretMutable = UnsafeMutablePointer(mutating: blindingSecretPointer)

                    pythia_buf_setup(transformedPasswordBuf, transformedPasswordMutable, 0, transformedPassword.count)
                    pythia_buf_setup(blindingSecretBuf, blindingSecretMutable, 0, blindingSecret.count)

                    return virgil_pythia_deblind(transformedPasswordBuf, blindingSecretBuf, deblindedPasswordBuf)

                }
            }
        }

        guard proxyResult == 0 else {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &deblindedPassword, from: deblindedPasswordBuf)

        return deblindedPassword
    }

    internal func computeTransformationKey(transformationKeyId: Data,
                                           pythiaSecret: Data,
                                           pythiaScopeSecret: Data) throws -> (Data, Data) {
        let transformationPrivateKeyCount = PYTHIA_BN_BUF_SIZE
        var transformationPrivateKey = Data(count: transformationPrivateKeyCount)
        let transformationPrivateKeyBuf = pythia_buf_new()!

        let transformationPublicKeyCount = PYTHIA_G1_BUF_SIZE
        var transformationPublicKey = Data(count: transformationPublicKeyCount)
        let transformationPublicKeyBuf = pythia_buf_new()!

        let transformationKeyIdBuf = pythia_buf_new()!
        let pythiaSecretBuf = pythia_buf_new()!
        let pythiaScopeSecretBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformationPrivateKeyBuf)
            pythia_buf_free(transformationPublicKeyBuf)
            pythia_buf_free(transformationKeyIdBuf)
            pythia_buf_free(pythiaSecretBuf)
            pythia_buf_free(pythiaScopeSecretBuf)
        }

        let proxyResult = transformationKeyId.withUnsafeBytes { (transformationKeyIdPointer: UnsafePointer<UInt8>) -> Int32 in
            pythiaSecret.withUnsafeBytes { (pythiaSecretPointer: UnsafePointer<UInt8>) -> Int32 in
                pythiaScopeSecret.withUnsafeBytes { (pythiaScopeSecretPointer: UnsafePointer<UInt8>) -> Int32 in

                    transformationPrivateKey.withUnsafeMutableBytes { (transformationPrivateKeyPointer: UnsafeMutablePointer<UInt8>) -> Int32 in
                        transformationPublicKey.withUnsafeMutableBytes { (transformationPublicKeyPointer: UnsafeMutablePointer<UInt8>) -> Int32 in

                            pythia_buf_setup(transformationPrivateKeyBuf, transformationPrivateKeyPointer, transformationPrivateKeyCount, 0)
                            pythia_buf_setup(transformationPublicKeyBuf, transformationPublicKeyPointer, transformationPublicKeyCount, 0)

                            let transformationKeyIdMutable = UnsafeMutablePointer(mutating: transformationKeyIdPointer)
                            let pythiaSecretMutable = UnsafeMutablePointer(mutating: pythiaSecretPointer)
                            let pythiaScopeSecretMutable = UnsafeMutablePointer(mutating: pythiaScopeSecretPointer)

                            pythia_buf_setup(transformationKeyIdBuf, transformationKeyIdMutable, 0, transformationKeyId.count)
                            pythia_buf_setup(pythiaSecretBuf, pythiaSecretMutable, 0, pythiaSecret.count)
                            pythia_buf_setup(pythiaScopeSecretBuf, pythiaScopeSecretMutable, 0, pythiaScopeSecret.count)

                            return virgil_pythia_compute_transformation_key_pair(transformationKeyIdBuf,
                                                                                 pythiaSecretBuf,
                                                                                 pythiaScopeSecretBuf,
                                                                                 transformationPrivateKeyBuf,
                                                                                 transformationPublicKeyBuf)
                        }
                    }
                }
            }
        }

        guard proxyResult == 0 else {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &transformationPrivateKey, from: transformationPrivateKeyBuf)
        VirgilPythia.trim(data: &transformationPublicKey, from: transformationPublicKeyBuf)

        return (transformationPrivateKey, transformationPublicKey)
    }

    internal func transform(blindedPassword: Data, tweak: Data, transformationPrivateKey: Data) throws -> (Data, Data) {
        let transformedPasswordBufCount = PYTHIA_GT_BUF_SIZE
        var transformedPassword = Data(count: transformedPasswordBufCount)
        let transformedPasswordBuf = pythia_buf_new()!

        let transformedTweakCount = PYTHIA_G2_BUF_SIZE
        var transformedTweak = Data(count: transformedTweakCount)
        let transformedTweakBuf = pythia_buf_new()!

        let blindedPasswordBuf = pythia_buf_new()!
        let tweakBuf = pythia_buf_new()!
        let transformationPrivateKeyBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(transformedTweakBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(tweakBuf)
            pythia_buf_free(transformationPrivateKeyBuf)
        }

        let proxyResult = blindedPassword.withUnsafeBytes { (blindedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
            tweak.withUnsafeBytes { (tweakPointer: UnsafePointer<UInt8>) -> Int32 in
                transformationPrivateKey.withUnsafeBytes { (transformationPrivateKeyPointer: UnsafePointer<UInt8>) -> Int32 in

                    transformedPassword.withUnsafeMutableBytes { (transformedPasswordPointer: UnsafeMutablePointer<UInt8>) -> Int32 in
                        transformedTweak.withUnsafeMutableBytes { (transformedTweakPointer: UnsafeMutablePointer<UInt8>) -> Int32 in

                            pythia_buf_setup(transformedPasswordBuf, transformedPasswordPointer, transformedPasswordBufCount, 0)
                            pythia_buf_setup(transformedTweakBuf, transformedTweakPointer, transformedTweakCount, 0)

                            let blindedPasswordMutable = UnsafeMutablePointer(mutating: blindedPasswordPointer)
                            let tweakMutable = UnsafeMutablePointer(mutating: tweakPointer)
                            let transformationPrivateKeyMutable = UnsafeMutablePointer(mutating: transformationPrivateKeyPointer)

                            pythia_buf_setup(blindedPasswordBuf, blindedPasswordMutable, 0, blindedPassword.count)
                            pythia_buf_setup(tweakBuf, tweakMutable, 0, tweak.count)
                            pythia_buf_setup(transformationPrivateKeyBuf, transformationPrivateKeyMutable, 0, transformationPrivateKey.count)

                            return virgil_pythia_transform(blindedPasswordBuf,
                                                           tweakBuf,
                                                           transformationPrivateKeyBuf,
                                                           transformedPasswordBuf,
                                                           transformedTweakBuf)
                        }
                    }
                }
            }
        }

        guard proxyResult == 0 else {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &transformedPassword, from: transformedPasswordBuf)
        VirgilPythia.trim(data: &transformedTweak, from: transformedTweakBuf)

        return (transformedPassword, transformedTweak)
    }

    internal func prove(transformedPassword: Data,
                        blindedPassword: Data,
                        transformedTweak: Data,
                        transformationPrivateKey: Data,
                        transformationPublicKey: Data) throws -> (Data, Data) {
        let proofValueCCount = PYTHIA_BN_BUF_SIZE
        var proofValueC = Data(count: proofValueCCount)
        let proofValueCBuf = pythia_buf_new()!

        let proofValueUCount = PYTHIA_BN_BUF_SIZE
        var proofValueU = Data(count: proofValueUCount)
        let proofValueUBuf = pythia_buf_new()!

        let transformedPasswordBuf = pythia_buf_new()!
        let blindedPasswordBuf = pythia_buf_new()!
        let transformedTweakBuf = pythia_buf_new()!
        let transformationPrivateKeyBuf = pythia_buf_new()!
        let transformationPublicKeyBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(proofValueCBuf)
            pythia_buf_free(proofValueUBuf)
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(transformedTweakBuf)
            pythia_buf_free(transformationPrivateKeyBuf)
            pythia_buf_free(transformationPublicKeyBuf)
        }

        let proxyResult = transformedPassword.withUnsafeBytes { (transformedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
            blindedPassword.withUnsafeBytes { (blindedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
                transformedTweak.withUnsafeBytes { (transformedTweakPointer: UnsafePointer<UInt8>) -> Int32 in
                    transformationPrivateKey.withUnsafeBytes { (transformationPrivateKeyPointer: UnsafePointer<UInt8>) -> Int32 in
                        transformationPublicKey.withUnsafeBytes { (transformationPublicKeyPointer: UnsafePointer<UInt8>) -> Int32 in

                            proofValueC.withUnsafeMutableBytes { (proofValueCPointer: UnsafeMutablePointer<UInt8>) -> Int32 in
                                proofValueU.withUnsafeMutableBytes { (proofValueUPointer: UnsafeMutablePointer<UInt8>) -> Int32 in

                                    pythia_buf_setup(proofValueCBuf, proofValueCPointer, proofValueCCount, 0)
                                    pythia_buf_setup(proofValueUBuf, proofValueUPointer, proofValueUCount, 0)

                                    let transformedPasswordMutable = UnsafeMutablePointer(mutating: transformedPasswordPointer)
                                    let blindedPasswordMutable = UnsafeMutablePointer(mutating: blindedPasswordPointer)
                                    let transformedTweakMutable = UnsafeMutablePointer(mutating: transformedTweakPointer)
                                    let transformationPrivateKeyMutable = UnsafeMutablePointer(mutating: transformationPrivateKeyPointer)
                                    let transformationPublicKeyMutable = UnsafeMutablePointer(mutating: transformationPublicKeyPointer)

                                    pythia_buf_setup(transformedPasswordBuf, transformedPasswordMutable, 0, transformedPassword.count)
                                    pythia_buf_setup(blindedPasswordBuf, blindedPasswordMutable, 0, blindedPassword.count)
                                    pythia_buf_setup(transformedTweakBuf, transformedTweakMutable, 0, transformedTweak.count)
                                    pythia_buf_setup(transformationPrivateKeyBuf, transformationPrivateKeyMutable, 0, transformationPrivateKey.count)
                                    pythia_buf_setup(transformationPublicKeyBuf, transformationPublicKeyMutable, 0, transformationPublicKey.count)

                                    return virgil_pythia_prove(transformedPasswordBuf,
                                                               blindedPasswordBuf,
                                                               transformedTweakBuf,
                                                               transformationPrivateKeyBuf,
                                                               transformationPublicKeyBuf,
                                                               proofValueCBuf,
                                                               proofValueUBuf)
                                }
                            }
                        }
                    }
                }
            }
        }

        guard proxyResult == 0 else {
            throw VirgilPythiaError.underlyingCryptoError
        }

        VirgilPythia.trim(data: &proofValueC, from: proofValueCBuf)
        VirgilPythia.trim(data: &proofValueU, from: proofValueUBuf)

        return (proofValueC, proofValueU)
    }

    internal func verify(transformedPassword: Data,
                         blindedPassword: Data,
                         tweak: Data,
                         transformationPublicKey: Data,
                         proofValueC: Data,
                         proofValueU: Data) -> Bool {
        let transformedPasswordBuf = pythia_buf_new()!
        let blindedPasswordBuf = pythia_buf_new()!
        let tweakBuf = pythia_buf_new()!
        let transformationPublicKeyBuf = pythia_buf_new()!
        let proofValueCBuf = pythia_buf_new()!
        let proofValueUBuf = pythia_buf_new()!

        defer {
            pythia_buf_free(transformedPasswordBuf)
            pythia_buf_free(blindedPasswordBuf)
            pythia_buf_free(tweakBuf)
            pythia_buf_free(transformationPublicKeyBuf)
            pythia_buf_free(proofValueCBuf)
            pythia_buf_free(proofValueUBuf)
        }

        var verified = Int32()

        let proxyResult = transformedPassword.withUnsafeBytes { (transformedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
            blindedPassword.withUnsafeBytes { (blindedPasswordPointer: UnsafePointer<UInt8>) -> Int32 in
                tweak.withUnsafeBytes { (tweakPointer: UnsafePointer<UInt8>) -> Int32 in
                    transformationPublicKey.withUnsafeBytes { (transformationPublicKeyPointer: UnsafePointer<UInt8>) -> Int32 in
                        proofValueC.withUnsafeBytes { (proofValueCPointer: UnsafePointer<UInt8>) -> Int32 in
                            proofValueU.withUnsafeBytes { (proofValueUPointer: UnsafePointer<UInt8>) -> Int32 in

                                let transformedPasswordMutable = UnsafeMutablePointer(mutating: transformedPasswordPointer)
                                let blindedPasswordMutable = UnsafeMutablePointer(mutating: blindedPasswordPointer)
                                let tweakMutable = UnsafeMutablePointer(mutating: tweakPointer)
                                let transformationPublicKeyMutable = UnsafeMutablePointer(mutating: transformationPublicKeyPointer)
                                let proofValueCMutable = UnsafeMutablePointer(mutating: proofValueCPointer)
                                let proofValueUMutable = UnsafeMutablePointer(mutating: proofValueUPointer)

                                pythia_buf_setup(transformedPasswordBuf, transformedPasswordMutable, 0, transformedPassword.count)
                                pythia_buf_setup(blindedPasswordBuf, blindedPasswordMutable, 0, blindedPassword.count)
                                pythia_buf_setup(tweakBuf, tweakMutable, 0, tweak.count)
                                pythia_buf_setup(transformationPublicKeyBuf, transformationPublicKeyMutable, 0, transformationPublicKey.count)
                                pythia_buf_setup(proofValueCBuf, proofValueCMutable, 0, proofValueC.count)
                                pythia_buf_setup(proofValueUBuf, proofValueUMutable, 0, proofValueU.count)

                                return virgil_pythia_verify(transformedPasswordBuf,
                                                            blindedPasswordBuf,
                                                            tweakBuf,
                                                            transformationPublicKeyBuf,
                                                            proofValueCBuf,
                                                            proofValueUBuf,
                                                            &verified)
                            }
                        }
                    }
                }
            }
        }

        guard proxyResult == 0 else {
            return false
        }

        return verified != 0
    }
}
