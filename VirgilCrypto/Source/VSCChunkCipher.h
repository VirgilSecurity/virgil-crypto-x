//
//  VSCChunkCipher.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/1/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSCBaseCipher.h"

/// Error domain constant for the VSCChunkCipher errors.
NS_SWIFT_NAME(kChunkCipherErrorDomain)
extern NSString * __nonnull const kVSCChunkCipherErrorDomain;

/**
 Class for performing encryption/decryption of relatively small parts of data.
 */
NS_SWIFT_NAME(ChunkCipher)
@interface VSCChunkCipher : VSCBaseCipher

/**
 Encrypts data from stream.

 @param source data to encrypt
 @param destination stream to receive encrypted data
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if succeeded, `NO` otherwise
 */
- (BOOL)encryptDataFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination error:(NSError * __nullable * __nullable)error;

/**
 Encrypts data from stream.

 @param source source data to encrypt
 @param destination stream to receive encrypted data
 @param chunkSize chunk size
 @param embedContentInfo determines whether to embed content info the the encrypted data, or not
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if succeeded, `NO` otherwise
 */
- (BOOL)encryptDataFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination preferredChunkSize:(size_t)chunkSize embedContentInfo:(BOOL)embedContentInfo error:(NSError * __nullable * __nullable)error;

/**
 Decrypts data from stream.

 @param source source data to decrypt
 @param destination stream to receive decrypted data
 @param password password
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if succeeded, `NO` otherwise
 */
- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

/**
 Decrypts data from stream.

 @param source source data to decrypt
 @param destination stream to receive decrypted data
 @param recipientId recipient id
 @param privateKey recipient's private key
 @param keyPassword recipient's private key password
 @param error `NSError` pointer to get an object in case of error, `nil` - otherwise.
 @return `YES` if succeeded, `NO` otherwise
 */
- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

@end
