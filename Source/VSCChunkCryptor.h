//
//  VSCChunkCryptor.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/1/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSCBaseCryptor.h"

/** 
 * Error domain constant for the VSCChunkCryptor errors.
 */
extern NSString * __nonnull const kVSCChunkCryptorErrorDomain;

/**
 * Class for performing encryption/decryption of relatively small parts of data.
 */
@interface VSCChunkCryptor : VSCBaseCryptor

- (void)encryptDataFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination error:(NSError * __nullable * __nullable)error;
- (void)encryptDataFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination preferredChunkSize:(size_t)chunkSize embedContentInfo:(BOOL)embedContentInfo error:(NSError * __nullable * __nullable)error;

- (void)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination error:(NSError * __nullable * __nullable)error;
- (void)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

- (void)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSData * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

@end
