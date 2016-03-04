//
//  VSSStreamSigner.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 3/2/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "VSSFoundationCommons.h"

extern NSString * __nonnull const kVSSStreamSignerErrorDomain;

@interface VSSStreamSigner : NSObject

- (instancetype __nonnull)initWithHash:(NSString * __nullable)hash NS_DESIGNATED_INITIALIZER;

- (NSData * __nullable)signStreamData:(NSInputStream * __nonnull)source privateKey:(NSData * __nonnull)privateKey keyPassword:(NSString * __nullable)keyPassword error:(NSError * __nullable * __nullable)error;

- (BOOL)verifySignature:(NSData * __nonnull)signature fromStream:(NSInputStream * __nonnull)source publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

@end
