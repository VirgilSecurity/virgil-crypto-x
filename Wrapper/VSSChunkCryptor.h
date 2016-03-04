//
//  VSSChunkCryptor.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/1/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSSBaseCryptor.h"

extern NSString * __nonnull const kVSSChunkCryptorErrorDomain;

@interface VSSChunkCryptor : VSSBaseCryptor

- (size_t)startEncryptionWithPreferredChunkSize:(size_t)chunkSize error:(NSError * __nullable * __nullable)error;

- (size_t)startDecryptionWithRecipientId:(NSString * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;
- (size_t)startDecryptionWithPassword:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

- (NSData * __nullable)processDataChunk:(NSData * __nonnull)chunk error:(NSError * __nullable * __nullable)error;
- (BOOL)finishWithError:(NSError * __nullable * __nullable)error;

@end
