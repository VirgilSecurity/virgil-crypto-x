//
//  VSSPBKDF.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 4/26/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

extern const size_t kVSSDefaultRandomBytesSize;
extern NSString * __nonnull const kVSSPBKDFErrorDomain;

typedef NS_ENUM(NSInteger, VSSPBKDFAlgorithm) {
    VSSPBKDFAlgorithmNone = 0,
    VSSPBKDFAlgorithmPBKDF2
};

typedef NS_ENUM(NSInteger, VSSPBKDFHash) {
    VSSPBKDFHashSHA1 = 1,
    VSSPBKDFHashSHA224,
    VSSPBKDFHashSHA256,
    VSSPBKDFHashSHA384,
    VSSPBKDFHashSHA512
};

@interface VSSPBKDF : NSObject

@property (nonatomic, strong, readonly) NSData * __nonnull salt;
@property (nonatomic, assign, readonly) unsigned int iterations;

@property (nonatomic, assign) VSSPBKDFAlgorithm algorithm;
@property (nonatomic, assign) VSSPBKDFHash hash;

/**
 * @brief Creates PBKDF wrapper object. By default algoritm is set to VSSPBKDFAlgorithmPBKDF2 and hash is set to VSSPBKDFHashSHA384.
 *
 * @param salt NSData with salt for key derivation. In case when salt.length == 0 default salt will be generated atomatically.
 * @param iterations unsigned int with count of iterations for key derivation function. In case of 0 - default iterations count will be used automatically.
 */
- (instancetype __nonnull)initWithSalt:(NSData * __nullable)salt iterations:(unsigned int)iterations NS_DESIGNATED_INITIALIZER;

/**
 * @brief Involve security check for used parameters.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 * @return BOOL YES in case of success, NO - otherwise.
 * @note Enabled by default.
 */
- (BOOL)enableRecommendationsCheckWithError:(NSError * __nullable * __nullable)error;

/**
 * @brief Ignore security check for used parameters.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 * @return BOOL YES in case of success, NO - otherwise.
 * @warning It's strongly recommended do not disable recommendations check.
 */
- (BOOL)disableRecommendationsCheckWithError:(NSError * __nullable * __nullable)error;

/**
 * @brief Derive key from the given password.
 *
 * @param password - password to use when generating key.
 * @param outSize - size of the output sequence, if 0 - then size of the underlying hash will be used.
 * @return Output sequence.
 */
- (NSData * __nullable)keyFromPassword:(NSString * __nonnull)password size:(size_t)size error:(NSError * __nullable * __nullable)error;

/**
 * @brief Generates cryptographically secure random bytes with required length.
 *
 * @param size size_t Required size in bytes of the generated array. When given size equals 0 then kVSSDefaultRandomBytesSize will be used instead.
 * @return NSData with cryptographically secure random bytes.
 */
+ (NSData * __nonnull)randomBytesOfSize:(size_t)size;

@end
