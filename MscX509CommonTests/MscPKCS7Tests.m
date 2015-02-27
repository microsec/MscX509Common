//
//  MscPKCS7Tests.m
//  MscX509Common
//
//  Created by Lendvai Richárd on 2015. 02. 25..
//  Copyright (c) 2015. Microsec. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <XCTest/XCTest.h>

#import "MscCertificateSigningRequest.h"
#import <openssl/evp.h>
#import "MscPKCS12.h"
#import "MscPKCS7.h"

@interface MscPKCS7Tests : XCTestCase {
    MscPKCS12 *pkcs12_1;
    MscPKCS12 *pkcs12_2;
    NSString *pkcs12_1_password;
    NSString *pkcs12_2_password;
}

@end

@implementation MscPKCS7Tests

- (void)setUp {
    [super setUp];
    
    NSError *error;
    OpenSSL_add_all_algorithms();
    
    pkcs12_1_password = @"kövérfülűsítúrázónő";
    pkcs12_2_password = @"ÁRVÍZTŰRŐTÜKÖRFÚRÓGÉP";
    
    MscRSAKey* rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:nil];
    
    MscX509Name *subject = [[MscX509Name alloc] init];
    subject.commonName = @"MscPKCS7 UnitTest1";
    subject.countryName = @"HU";
    subject.organizationName = @"Microsec Ltd.";
    
    MscCertificateSigningRequest *csr1 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"123456" error:&error];
    [csr1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:nil];
    
    subject.commonName = @"MscPKCS7 UnitTest1";
    MscCertificateSigningRequest *csr2 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"almafa" error:&error];
    [csr2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:nil];
    
    MscCertificate* cer1 = [[MscCertificate alloc] initWithRequest:csr1 error:&error];
    [cer1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:nil];
    
    MscCertificate* cer2 = [[MscCertificate alloc] initWithRequest:csr2 error:&error];
    [cer2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:nil];
    
    pkcs12_1 = [[MscPKCS12 alloc] initWithRSAKey:rsaKey certificate:cer1 password:pkcs12_1_password error:&error];
    XCTAssertNotNil(pkcs12_1, @"Failed to initialize MscPKCS12");
    XCTAssertNil(error, @"MscPKCS12 initialization returned with error");
    
    pkcs12_2 = [[MscPKCS12 alloc] initWithRSAKey:rsaKey certificate:cer2 password:pkcs12_2_password error:&error];
    XCTAssertNotNil(pkcs12_2, @"Failed to initialize MscPKCS12");
    XCTAssertNil(error, @"MscPKCS12 initialization returned with error");
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSign {
    
    NSString* toBeSignedString = @"Sign this!";
    NSData* toBeSignedData = [toBeSignedString dataUsingEncoding:NSUTF8StringEncoding];
    
    MscX509CommonError* localError;
    MscPKCS7* p7 = [[MscPKCS7 alloc] init];
    NSData* signedData = [p7 signData:toBeSignedData key:pkcs12_1 password:pkcs12_1_password error:&localError];
    XCTAssertNotNil(signedData, @"Failed to sign data");
    XCTAssertNil(localError, @"Failed to sign data");
}

@end
