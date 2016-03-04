//
//  VSSStreamCryptor.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 2/25/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import "VSSBaseCryptor.h"

extern NSString * __nonnull const kVSSStreamCryptorErrorDomain;

@interface VSSStreamCryptor : VSSBaseCryptor

- (BOOL)encryptDataFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination embedContentInfo:(BOOL)embedContentInfo error:(NSError * __nullable * __nullable)error;

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination recipientId:(NSString * __nonnull)recipientId privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

- (BOOL)decryptFromStream:(NSInputStream * __nonnull)source toStream:(NSOutputStream * __nonnull)destination password:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

@end
