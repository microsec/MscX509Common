//
//  MscRSAKey.m
//  MscSCEP
//
//  Created by Microsec on 2014.01.27..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import "MscRSAKey.h"
#import "MscRSAKey_OpenSSL_RSA.h"
#import "MscX509CommonLocalException.h"
#import "NSString+MscASCIIExtension.h"

#import <openssl/rsa.h>
#import <openssl/pem.h>

@implementation MscRSAKey

@synthesize _rsa, _evp_pkey = _mEVP_pkey;

-(id)initWithKeySize:(KeySize)keySize error:(MscX509CommonError**)error {
    
    if (self = [super init]) {
        
        BIGNUM *bigNumber = NULL;
        RSA *rsa = NULL;
        
        @try {
        
            int returnCode;
        
            if (!keySize) {
                NSLog(@"Failed to generate key, keySize parameter missing");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToGenerateKey];
            }
        
            bigNumber = BN_new();
            if (!bigNumber) {
                NSLog(@"Failed to allocate memory for variable: bigNumber");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToAllocateMemory];
            }
        
            rsa = RSA_new();
            if (!rsa) {
                NSLog(@"Failed to allocate memory for variable: rsa");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToAllocateMemory];
            }
        
            returnCode = BN_set_word(bigNumber, RSA_F4);
            if (returnCode != 1) {
                NSLog(@"Failed to generate key, function BN_set_word returned with %d", returnCode);
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToGenerateKey];
            }
        
            returnCode = RSA_generate_key_ex(rsa, keySize, bigNumber, NULL);
            if (returnCode != 1) {
                NSLog(@"Failed to generate RSA key, function RSA_generate_key_ex returned with %d", returnCode);
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToGenerateKey];
            }
            
            _rsa = rsa;
            
            return self;
        }
        @catch (MscX509CommonLocalException *e) {
            
            if (error) {
                *error = [MscX509CommonError errorWithCode:e.errorCode];
            }
            RSA_free(rsa);
            return nil;
        }
        @finally {
            
            BN_free(bigNumber);
        }
    }
    return nil;
}

-(id)initWithContentsOfFile:(NSString *)path error:(MscX509CommonError**)error {
    
    if (self = [super init]) {
        FILE* file = NULL;
        RSA *rsa = NULL;
        
        @try {
            
            file = fopen([path fileSystemRepresentation], "r");
            if (!file) {
                NSLog(@"Failed to open file for read: %@", path);
                @throw [MscX509CommonLocalException exceptionWithCode:IOError];
            }
            
            rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            if (!rsa) {
                NSLog(@"Failed to read key file");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToReadKey];
            }
            _rsa = rsa;
            
            return self;
        }
        @catch (MscX509CommonLocalException *e) {
            
            if (error) {
                *error = [MscX509CommonError errorWithCode:e.errorCode];
            }
            RSA_free(rsa);
            return nil;
        }
        @finally {
            fclose(file);
        }
    }
    return nil;
}

-(void)saveToPath:(NSString *)path error:(MscX509CommonError **)error {
    
    FILE* file = NULL;
    
    @try {
        
        int returnCode;
        
        file = fopen([path fileSystemRepresentation], "w");
        if (!file) {
            NSLog(@"Failed to open file for write: %@", path);
            @throw [MscX509CommonLocalException exceptionWithCode:IOError];
        }
        
        returnCode = PEM_write_RSAPrivateKey(file, _rsa, NULL, NULL, 0, NULL, NULL);
        if (returnCode != 1) {
            NSLog(@"Failed to write key file, function PEM_write_RSAPrivateKey returned with %d", returnCode);
            @throw [MscX509CommonLocalException exceptionWithCode:FailedToWriteKey];
        }
    }
    @catch (MscX509CommonLocalException *e) {
        
        if (error) {
            *error = [MscX509CommonError errorWithCode:e.errorCode];
        }
        return;
    }
    @finally {
        
        fclose(file);
    }
}

- (void)encodeWithCoder:(NSCoder *)aCoder {
    
    unsigned char *rsaData = NULL;
    
    @try {
        
        int rsaDataLength = i2d_RSAPrivateKey(_rsa, &rsaData);
        
        if (rsaDataLength < 1) {
            NSLog(@"Failed to encode key, function i2d_RSAPrivateKey returned with %d", rsaDataLength);
            @throw [MscX509CommonLocalException exceptionWithCode:FailedToEncodeKey];
        }
        
        [aCoder encodeBytes:rsaData length:rsaDataLength forKey:@"rsaData"];
    }
    @finally {
        
        OPENSSL_free(rsaData);
    }
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    
    if (self = [super init]) {
        
        RSA *rsa = NULL;
        const unsigned char *rsaData = NULL;
        
        @try {
            
            NSUInteger rsaDataLength;
            
            rsaData = [aDecoder decodeBytesForKey:@"rsaData" returnedLength:&rsaDataLength];
            if (rsaDataLength < 1) {
                NSLog(@"Failed to decode key, function decodeBytesForKey returned with %lu",(unsigned long)rsaDataLength);
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToDecodeKey];
            }
            
            rsa = d2i_RSAPrivateKey(NULL, &rsaData, (unsigned long)rsaDataLength);
            if (rsa == NULL) {
                NSLog(@"Failed to decode key, function: d2i_RSAPrivateKey");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToDecodeKey];
            }
            _rsa = rsa;
            
            return self;
            
        }
        @catch (MscX509CommonLocalException *e) {
            
            RSA_free(rsa);
            return nil;
        }
    }
    return nil;
}

-(BOOL)isEqualToMscRSA:(MscRSAKey*)otherMscRSAKey {
    
    
    unsigned char *myRsaData = NULL;
    unsigned char *otherRsaData = NULL;
    
    @try {
        
        int myRsaDataLength = i2d_RSAPrivateKey(_rsa, &myRsaData);
        int otherRsaDataLength = i2d_RSAPrivateKey(otherMscRSAKey._rsa, &otherRsaData);
        
        if (myRsaDataLength < 1) {
            NSLog(@"Failed to read key, function i2d_RSAPrivateKey returned with %d", myRsaDataLength);
            @throw [MscX509CommonLocalException exceptionWithCode:FailedToReadKey];
        }
        
        if (otherRsaDataLength < 1) {
            NSLog(@"Failed to read key, function i2d_RSAPrivateKey returned with %d", otherRsaDataLength);
            @throw [MscX509CommonLocalException exceptionWithCode:FailedToReadKey];
        }
        
        if (myRsaDataLength != otherRsaDataLength) {
            return NO;
        }
        
        return memcmp(myRsaData, otherRsaData, myRsaDataLength) == 0;
    }
    @finally {
        
        OPENSSL_free(myRsaData);
        OPENSSL_free(otherRsaData);
        
    }
}

-(EVP_PKEY*)_evp_pkey {
    
    if (!_mEVP_pkey) {
        
        @try {
            
            int returnCode;
        
            _mEVP_pkey = EVP_PKEY_new();
            if (!_mEVP_pkey) {
                NSLog(@"Failed to allocate memory for variable: _mEVP_pkey");
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToAllocateMemory];
            }
            
            returnCode = EVP_PKEY_set1_RSA(_mEVP_pkey, _rsa);
            if (returnCode != 1) {
                NSLog(@"Failed to generate key, function EVP_PKEY_set1_RSA returned with %d", returnCode);
                @throw [MscX509CommonLocalException exceptionWithCode:FailedToGenerateKey];
            }
            
            return _mEVP_pkey;
        }
        @catch (MscX509CommonLocalException *e) {
            
            EVP_PKEY_free(_mEVP_pkey);
            return nil;
        }
    }
    return _mEVP_pkey;
}

-(void)dealloc {
    RSA_free(_rsa);
    EVP_PKEY_free(_mEVP_pkey);
}

@end
