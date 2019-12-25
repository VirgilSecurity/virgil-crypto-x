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
    internal enum InputOutput {
        case data(input: Data)
        case stream(input: InputStream, streamSize: Int?, output: OutputStream)
    }

    internal enum SigningMode {
        case signAndEncrypt
        case signThenEncrypt
    }

    internal enum VerifyingMode {
        case decryptAndVerify
        case decryptThenVerify
        case any
    }

    internal struct SigningOptions {
        let privateKey: VirgilPrivateKey
        let mode: SigningMode
    }

    internal struct VerifyingOptions {
        let publicKeys: [VirgilPublicKey]
        let mode: VerifyingMode
    }

    private func startEncryption(cipher: RecipientCipher,
                                 inputOutput: InputOutput,
                                 signingOptions: SigningOptions?) throws {
        if let signingOpt = signingOptions {
            switch signingOpt.mode {
            case .signAndEncrypt:
                switch inputOutput {
                case .data(let input):
                    let signature = try self.generateSignature(of: input, using: signingOpt.privateKey)
                    cipher.customParams().addData(key: VirgilCrypto.CustomParamKeySignature,
                                                  value: signature)
                    cipher.customParams().addData(key: VirgilCrypto.CustomParamKeySignerId,
                                                  value: signingOpt.privateKey.identifier)
                case .stream:
                    fatalError("signAndEncrypt is not supported for streams")
                }
                try cipher.startEncryption()

            case .signThenEncrypt:
                cipher.setSignerHash(signerHash: Sha512())
                try cipher.addSigner(signerId: signingOpt.privateKey.identifier, privateKey: signingOpt.privateKey.key)

                var size: Int

                switch inputOutput {
                case .data(let input):
                    size = input.count
                case .stream(_, let streamSize, _):
                    guard let streamSize = streamSize else {
                        fatalError("signThenEncrypt for streams with unknown size is not supported")
                    }
                    size = streamSize
                }

                try cipher.startSignedEncryption(dataSize: size)
            }
        }
        else {
            try cipher.startEncryption()
        }
    }

    private func processEncryption(cipher: RecipientCipher,
                                   inputOutput: InputOutput,
                                   signingOptions: SigningOptions?) throws -> Data? {
        switch inputOutput {
        case let .data(inputData):
            var result = cipher.packMessageInfo()

            result += try cipher.processEncryption(data: inputData)

            result += try cipher.finishEncryption()

            if let signingOpt = signingOptions, signingOpt.mode == .signThenEncrypt {
                result += try cipher.packMessageInfoFooter()
            }

            return result

        case let .stream(inputStream, streamSize, outputStream):
            if inputStream.streamStatus == .notOpen {
                inputStream.open()
            }
            if outputStream.streamStatus == .notOpen {
                outputStream.open()
            }

            try StreamUtils.write(cipher.packMessageInfo(), to: outputStream)

            try StreamUtils.forEachChunk(in: inputStream, streamSize: streamSize) {
                try StreamUtils.write(try cipher.processEncryption(data: $0), to: outputStream)
            }

            try StreamUtils.write(try cipher.finishEncryption(), to: outputStream)

            if let signingOpt = signingOptions, signingOpt.mode == .signThenEncrypt {
                try StreamUtils.write(try cipher.packMessageInfoFooter(), to: outputStream)
            }

            return nil
        }
    }

    /// Padding length
    @objc public static let paddingLen = 160

    internal func encrypt(inputOutput: InputOutput,
                          signingOptions: SigningOptions?,
                          recipients: [VirgilPublicKey],
                          enablePadding: Bool) throws -> Data? {
        let aesGcm = Aes256Gcm()
        let cipher = RecipientCipher()

        cipher.setEncryptionCipher(encryptionCipher: aesGcm)
        cipher.setRandom(random: self.rng)

        if enablePadding {
            let padding = RandomPadding()
            padding.setRandom(random: self.rng)
            cipher.setEncryptionPadding(encryptionPadding: padding)
            let paddingParams = PaddingParams(frame: VirgilCrypto.paddingLen,
                                              frameMax: VirgilCrypto.paddingLen)
            cipher.setPaddingParams(paddingParams: paddingParams)
        }

        recipients.forEach {
            cipher.addKeyRecipient(recipientId: $0.identifier, publicKey: $0.key)
        }

        try self.startEncryption(cipher: cipher, inputOutput: inputOutput, signingOptions: signingOptions)

        return try self.processEncryption(cipher: cipher, inputOutput: inputOutput, signingOptions: signingOptions)
    }

    private func processDecryption(cipher: RecipientCipher,
                                   inputOutput: InputOutput) throws -> Data? {
        switch inputOutput {
        case let .stream(inputStream, _, outputStream):
            if inputStream.streamStatus == .notOpen {
                inputStream.open()
            }
            if outputStream.streamStatus == .notOpen {
                outputStream.open()
            }

            try StreamUtils.forEachChunk(in: inputStream, streamSize: nil) {
                try StreamUtils.write(try cipher.processDecryption(data: $0), to: outputStream)
            }
            try StreamUtils.write(try cipher.finishDecryption(), to: outputStream)

            return nil

        case let .data(input):
            var result = try cipher.processDecryption(data: input)

            result += try cipher.finishDecryption()

            return result
        }
    }

    private func verifyPlainSignature(cipher: RecipientCipher,
                                      inputOutput: InputOutput,
                                      result: Data?,
                                      publicKeys: [VirgilPublicKey]) throws {
        guard case InputOutput.data(_) = inputOutput else {
            fatalError("signAndEncrypt is not supported for streams")
        }

        let signerPublicKey: VirgilPublicKey

        if publicKeys.count == 1 {
            signerPublicKey = publicKeys[0]
        }
        else {
            let signerId: Data

            do {
                signerId = try cipher.customParams().findData(key: VirgilCrypto.CustomParamKeySignerId)
            }
            catch {
                throw VirgilCryptoError.signerNotFound
            }

            guard let publicKey = publicKeys.first(where: { $0.identifier == signerId }) else {
                throw VirgilCryptoError.signerNotFound
            }

            signerPublicKey = publicKey
        }

        let signature: Data

        do {
            signature = try cipher.customParams().findData(key: VirgilCrypto.CustomParamKeySignature)
        }
        catch {
            throw VirgilCryptoError.signatureNotFound
        }

        guard try self.verifySignature(signature, of: result!, with: signerPublicKey) else {
            throw VirgilCryptoError.signatureNotVerified
        }
    }

    private func verifyEncryptedSignature(cipher: RecipientCipher,
                                          publicKeys: [VirgilPublicKey]) throws {
        guard cipher.isDataSigned() else {
            throw VirgilCryptoError.dataIsNotSigned
        }

        let signerInfoList = cipher.signerInfos()

        guard signerInfoList.hasItem() && !signerInfoList.hasNext() else {
            throw VirgilCryptoError.dataIsNotSigned
        }

        let signerInfo = signerInfoList.item()

        guard let signerPublicKey = publicKeys
            .first(where: { $0.identifier == signerInfo.signerId() }) else {
            throw VirgilCryptoError.signerNotFound
        }

        guard cipher.verifySignerInfo(signerInfo: signerInfo, publicKey: signerPublicKey.key) else {
            throw VirgilCryptoError.signatureNotVerified
        }
    }

    private func finishDecryption(cipher: RecipientCipher,
                                  inputOutput: InputOutput,
                                  result: Data?,
                                  verifyingOptions: VerifyingOptions?) throws {
        guard let verifyingOptions = verifyingOptions else {
            return
        }

        var mode = verifyingOptions.mode

        if mode == .any {
            mode = cipher.isDataSigned() ? .decryptThenVerify : .decryptAndVerify
        }

        switch mode {
        case .decryptAndVerify:
            try self.verifyPlainSignature(cipher: cipher,
                                          inputOutput: inputOutput,
                                          result: result,
                                          publicKeys: verifyingOptions.publicKeys)

        case .decryptThenVerify:
            try self.verifyEncryptedSignature(cipher: cipher, publicKeys: verifyingOptions.publicKeys)

        case .any:
            fatalError()
        }
    }

    internal func decrypt(inputOutput: InputOutput,
                          verifyingOptions: VerifyingOptions?,
                          privateKey: VirgilPrivateKey) throws -> Data? {
        let cipher = RecipientCipher()
        cipher.setRandom(random: self.rng)

        let paddingParams = PaddingParams(frame: VirgilCrypto.paddingLen,
                                          frameMax: VirgilCrypto.paddingLen)
        cipher.setPaddingParams(paddingParams: paddingParams)

        try cipher.startDecryptionWithKey(recipientId: privateKey.identifier,
                                          privateKey: privateKey.key,
                                          messageInfo: Data())

        let result = try self.processDecryption(cipher: cipher, inputOutput: inputOutput)

        try self.finishDecryption(cipher: cipher,
                                  inputOutput: inputOutput,
                                  result: result,
                                  verifyingOptions: verifyingOptions)

        return result
    }
}
