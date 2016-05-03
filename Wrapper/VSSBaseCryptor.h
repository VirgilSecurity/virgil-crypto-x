//
//  VSSBaseCryptor.h
//  VirgilCypto
//
//  Created by Pavel Gorb on 2/23/16.
//  Copyright © 2016 VirgilSecurity. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString * __nonnull const kVSSBaseCryptorErrorDomain;

@interface VSSBaseCryptor : NSObject

@property (nonatomic, assign, readonly) void * __nullable llCryptor;

/**
 * Adds given public key as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using key-based encryption.
 * @deprecated Use -addKeyRecipient:publicKey:error: instead.
 *
 * @param recipientId NSString String containing identifier for the public key used for encryption.
 * @param publicKey NSData Data object containing public key which will be used for encryption.
 */
- (void)addKeyRecipient:(NSString * __nonnull)recipientId publicKey:(NSData * __nonnull)publicKey __attribute__((deprecated("Use -addKeyRecipient:publicKey:error: instead.")));

/**
 * Adds given public key as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using key-based encryption.
 * @param recipientId NSString String containing identifier for the public key used for encryption.
 * @param publicKey NSData Data object containing public key which will be used for encryption.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)addKeyRecipient:(NSString * __nonnull)recipientId publicKey:(NSData * __nonnull)publicKey error:(NSError * __nullable * __nullable)error;

/**
 * @brief Removes a public key with given identifier from the recipients list for encryption.
 * @deprecated Use -removeKeyRecipient:error: instead.
 *
 * @param recipientId NSString String containing identifier for the public key which should be removed.
 */
- (void)removeKeyRecipient:(NSString * __nonnull)recipientId __attribute__((deprecated("Use -removeKeyRecipient:error: instead.")));

/**
 * @brief Removes a public key with given identifier from the recipients list for encryption.
 *
 * @param recipientId NSString String containing identifier for the public key which should be removed.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removeKeyRecipient:(NSString * __nonnull)recipientId error:(NSError * __nullable * __nullable)error;

/**
 * @brief Adds given password as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using pasword-based encryption.
 * @deprecated Use -addPasswordRecipient:error: instead.
 *
 * @param password NSString Password which will be used for encryption.
 */
- (void)addPasswordRecipient:(NSString * __nonnull)password __attribute__((deprecated("Use -addPasswordRecipient:error: instead.")));

/**
 * @brief Adds given password as a recipient for encryption. This method should be called before -encryptData:embedContentInfo: in case of using pasword-based encryption.
 *
 * @param password NSString Password which will be used for encryption.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)addPasswordRecipient:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

/**
 * @brief Removes given password from the recipients list for encryption.
 * @deprecated Use -removePasswordRecipient:error: instead.
 *
 * @param password NSString Password which should be removed.
 */
- (void)removePasswordRecipient:(NSString * __nonnull)password __attribute__((deprecated("Use -removePasswordRecipient:error: instead.")));

/**
 * @brief Removes given password from the recipients list for encryption.
 *
 * @param password NSString Password which should be removed.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 * 
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removePasswordRecipient:(NSString * __nonnull)password error:(NSError * __nullable * __nullable)error;

/**
 * @brief Removes all recepients which would be used for encryption.
 * @deprecated Use -removeAllRecipientsWithError: instead.
 */
- (void)removeAllRecipients __attribute__((deprecated("Use -removeAllRecipientsWithError: instead")));

/**
 * @brief Removes all recepients which would be used for encryption.
 *
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removeAllRecipientsWithError:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to get the content info data with information about the encryption recipients in case of parameter embedContentInfo of the -encryptData:embedContentInfo: is set to @NO or nil.
 * @deprecated Use -contentInfoWithError: instead.
 *
 * @return NSData Data object with content info for encryption data or nil in case of error or if no content info present.
 */
- (NSData * __nullable)contentInfo __attribute__((deprecated("Use -contentInfoWithError: instead.")));

/**
 * Allows to get the content info data with information about the encryption recipients in case of parameter embedContentInfo of the -encryptData:embedContentInfo: is set to @NO or nil.
 *
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSData Data object with content info for encryption data or nil in case of error or if no content info present.
 */
- (NSData * __nullable)contentInfoWithError:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to set the content info data with information about the encryption recipients before any calls to -decryptData: methods in case when data was encrypted with parameter embedContentInfo of the -encryptData:embedContentInfo: was set to @NO or nil.
 * @deprecated Use -setContentInfo:error: instead.
 *
 * @param NSData Data object with content info for the data decryption.
 */
- (void)setContentInfo:(NSData * __nonnull)contentInfo __attribute__((deprecated("Use -setContentInfo:error: instead.")));

/**
 * Allows to set the content info data with information about the encryption recipients before any calls to -decryptData: methods in case when data was encrypted with parameter embedContentInfo of the -encryptData:embedContentInfo: was set to false.
 *
 * @param NSData Data object with content info for the data decryption.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)setContentInfo:(NSData * __nonnull)contentInfo error:(NSError * __nullable * __nullable)error;

/**
 * @brief Calculates content info size which is a part of the given data.
 *
 * @param data NSData Data object with content size it it.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 
 * @return Size of the content info if it exists as part of the data, 0 - otherwise.
 */
- (size_t)contentInfoSizeInData:(NSData * __nonnull)data error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to set integer value for custom parameter name as a part of the content info in unencrypted form.
 *
 * @param value int value which have to be stored for parameter name given as a key.
 * @param key NSString custom parameter name. The same parameter name can be used also for -setString:forKey:error: and -setData:forKey:error to save 3 different values at the same time.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 * 
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)setInt:(int)value forKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to get integer value for custom parameter name which has been set earlier.
 *
 * @param key NSString custom parameter name.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return int value for given parameter name. In case of error returns 0 and NSError in error parameter.
 */
- (int)intForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to remove int value for custom parameter which has been set earlier.
 *
 * @param key NSString custom parameter name. If there is no given int parameter present - just does nothing and returns YES.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removeIntForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to set string value for custom parameter name as a part of the content info in unencrypted form.
 *
 * @param value NSString value which have to be stored for parameter name given as a key.
 * @param key NSString custom parameter name. The same parameter name can be used also for -setInt:forKey:error: and -setData:forKey:error to save 3 different values at the same time.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)setString:(NSString * __nonnull)value forKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to get string value for custom parameter name which has been set earlier.
 *
 * @param key NSString custom parameter name.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSString value for given parameter name. In case of error returns nil and NSError in error parameter.
 */
- (NSString * __nullable)stringForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to remove string value for custom parameter which has been set earlier.
 *
 * @param key NSString custom parameter name. If there is no given string parameter present - just does nothing and returns YES.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removeStringForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to set data value for custom parameter name as a part of the content info in unencrypted form.
 *
 * @param value NSData value which have to be stored for parameter name given as a key.
 * @param key NSString custom parameter name. The same parameter name can be used also for -setInt:forKey:error: and -setString:forKey:error to save 3 different values at the same time.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)setData:(NSData * __nonnull)value forKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to get data value for custom parameter name which has been set earlier.
 *
 * @param key NSString custom parameter name.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NSData value for given parameter name. In case of error returns nil and NSError in error parameter.
 */
- (NSData * __nullable)dataForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Allows to remove data value for custom parameter which has been set earlier.
 *
 * @param key NSString custom parameter name. If there is no given data parameter present - just does nothing and returns YES.
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return BOOL YES in case when operation completed successfully, NO - otherwise.
 */
- (BOOL)removeDataForKey:(NSString * __nonnull)key error:(NSError * __nullable * __nullable)error;

/**
 * @brief Checks if there are any custom parameters set.
 *
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return NO in case there is no any parameter. YES - otherwise. In case of error - returns YES and NSError object in error parameter.
 */
- (BOOL)isEmptyCustomParametersWithError:(NSError * __nullable * __nullable)error;

/**
 * @brief Removes all custom parameters.
 *
 * @param error NSError pointer to get an object in case of error, nil - otherwise.
 *
 * @return YES in case when operation completed successfully, NO - otherwise. In case of error - returns NO and NSError object in error parameter.
 */
- (BOOL)clearCustomParametersWithError:(NSError * __nullable * __nullable)error;

@end
