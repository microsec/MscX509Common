//
//  MscPKCS12Tests.m
//  MscX509Common
//
//  Created by Microsec on 2014.06.24..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "MscCertificateSigningRequest.h"
#import "MscRSAKey.h"
#import "MscCertificate.h"
#import <openssl/evp.h>
#import "MscPKCS12.h"

@interface MscPKCS12Tests : XCTestCase {
    MscCertificate *cer1;
    MscCertificate *cer2;
    MscPKCS12 *pfx1;
    MscPKCS12 *pfx2;
    NSString *password1;
    NSString *password2;
    NSString *filePath;
    NSString *filePathPfx1;
    NSString *filePathPfx2;
    MscRSAKey *rsaKey;
}

@end

@implementation MscPKCS12Tests

- (void)setUp
{
    [super setUp];
    
    NSError *error;
    OpenSSL_add_all_algorithms();
    
    password1 = @"kövérfülűsítúrázónő";
    password2 = @"ÁRVÍZTŰRŐTÜKÖRFÚRÓGÉP";
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    filePath = [documentsDirectory stringByAppendingPathComponent:@"pkcs12_objects.xml"];
    filePathPfx1 = [documentsDirectory stringByAppendingPathComponent:@"pkcs12_1.pfx"];
    filePathPfx2 = [documentsDirectory stringByAppendingPathComponent:@"pkcs12_2.pfx"];
    rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:nil];
    
    MscX509Name *subject = [[MscX509Name alloc] init];
    subject.commonName = @"UnitTest1";
    subject.countryName = @"HU";
    subject.organizationName = @"Microsec Ltd.";
    
    MscCertificateSigningRequest *csr1 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"123456" error:&error];
    [csr1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:nil];
    
    subject.commonName = @"UnitTest2";
    MscCertificateSigningRequest *csr2 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"almafa" error:&error];
    [csr2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:nil];
    
    cer1 = [[MscCertificate alloc] initWithRequest:csr1 error:&error];
    [cer1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:nil];
    
    cer2 = [[MscCertificate alloc] initWithRequest:csr2 error:&error];
    [cer2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:nil];
    
    pfx1 = [[MscPKCS12 alloc] initWithRSAKey:rsaKey certificate:cer1 password:password1 error:&error];
    XCTAssertNotNil(pfx1, @"Failed to initialize MscPKCS12");
    XCTAssertNil(error, @"MscPKCS12 initialization returned with error");
    
    pfx2 = [[MscPKCS12 alloc] initWithRSAKey:rsaKey certificate:cer2 password:password2 error:&error];
    XCTAssertNotNil(pfx2, @"Failed to initialize MscPKCS12");
    XCTAssertNil(error, @"MscPKCS12 initialization returned with error");
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSaveAndLoad
{
    NSError *error;
    [pfx1 saveToPath:filePathPfx1 error:&error];
    XCTAssertNil(error, @"Failed to save MscPKCS12");
    
    [pfx2 saveToPath:filePathPfx2 error:&error];
    XCTAssertNil(error, @"Failed to save MscPKCS12");
    
    MscPKCS12* savedPkcs12_1 = [[MscPKCS12 alloc] initWithContentsOfFile:filePathPfx1 error:&error];
    XCTAssertNotNil(savedPkcs12_1, @"Failed to initialize MscPKCS12 from filesystem");
    XCTAssertTrue([pfx1 isEqualToMscPKCS12:savedPkcs12_1], @"MscPKCS12 objects are not equal");
    
    MscPKCS12* savedPkcs12_2 = [[MscPKCS12 alloc] initWithContentsOfFile:filePathPfx2 error:&error];
    XCTAssertNotNil(savedPkcs12_2, @"Failed to initialize MscPKCS12 from filesystem");
    XCTAssertTrue([pfx2 isEqualToMscPKCS12:savedPkcs12_2], @"MscPKCS12 objects are not equal");
}

-(void)testSign {
    
    
    MscX509CommonError* signError;
    NSString* data = @"60d33ebbf3bc83a27814af22e5b0604088a635e5da0995f749289bf11d0edcea";
    NSData* d = [[NSData alloc] initWithBase64EncodedString:data options:0];
    
    NSData* signedHash1 = [rsaKey signHash:d error:&signError];
    XCTAssertNil(signError, @"Failed to sign hash");
    NSData* signedHash2 = [pfx1 signHash:d password:password1 error:&signError];
    XCTAssertNil(signError, @"Failed to sign hash");
    
    XCTAssertEqualObjects(signedHash1, signedHash2, @"Signatures are not equal");
}

-(void)testSerializeAndDeserialize
{
    NSArray *pkcs12_objects = [[NSArray alloc] initWithObjects:pfx1, pfx2, nil];
    [NSKeyedArchiver archiveRootObject:pkcs12_objects toFile:filePath];
    
    NSMutableArray* savedPkcs12_objects = [NSKeyedUnarchiver unarchiveObjectWithFile:filePath];
    XCTAssertEqual([savedPkcs12_objects count], [pkcs12_objects count], @"Failed to deserialize pkcs12_objects");
    
    for (int i = 0; i < [pkcs12_objects count]; i++) {
        MscPKCS12* pkcs12 = [pkcs12_objects objectAtIndex:i];
        MscPKCS12* savedPkcs12 = [savedPkcs12_objects objectAtIndex:i];
        XCTAssertTrue([pkcs12 isEqualToMscPKCS12:savedPkcs12], @"MscPKCS12 objects are not equal");
    }
}

@end
