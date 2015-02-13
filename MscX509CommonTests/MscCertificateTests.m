//
//  MscCertificateTests.m
//  MscX509Common
//
//  Created by Microsec on 2014.06.20..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "MscCertificate.h"
#import <openssl/evp.h>

@interface MscCertificateTests : XCTestCase{
    MscCertificateSigningRequest *csr1;
    MscCertificateSigningRequest *csr2;
    MscCertificate *cer1;
    MscCertificate *cer2;
    NSString *filePath;
    NSString *filePathCer1;
    NSString *filePathCer2;
    MscRSAKey *rsaKey;
}

@end

@implementation MscCertificateTests

- (void)setUp
{
    [super setUp];
    
    NSError *error;
    OpenSSL_add_all_algorithms();
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    filePath = [documentsDirectory stringByAppendingPathComponent:@"certificates.xml"];
    filePathCer1 = [documentsDirectory stringByAppendingPathComponent:@"cer1.cer"];
    filePathCer2 = [documentsDirectory stringByAppendingPathComponent:@"cer2.cer"];
    rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:nil];
    
    MscX509Name *subject = [[MscX509Name alloc] init];
    subject.commonName = @"UnitTest1";
    subject.countryName = @"HU";
    subject.organizationName = @"Microsec Ltd.";
    
    csr1 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"123456" error:&error];
    [csr1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:nil];
    
    subject.commonName = @"UnitTest2";
    csr2 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"almafa" error:&error];
    [csr2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:nil];
    
    cer1 = [[MscCertificate alloc] initWithRequest:csr1 error:&error];
    XCTAssertNil(error, @"Failed to initialize MscCertificate");
    
    cer2 = [[MscCertificate alloc] initWithRequest:csr2 error:&error];
    XCTAssertNil(error, @"Failed to initialize MscCertificate");
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSaveAndLoad
{
    NSError *error;
    [cer1 saveToPath:filePathCer1 error:&error];
    XCTAssertNil(error, @"Failed to save MscCertificate");
    
    [cer2 saveToPath:filePathCer2 error:&error];
    XCTAssertNil(error, @"Failed to save MscCertificate");
    
    MscCertificate* savedCer1 = [[MscCertificate alloc] initWithContentsOfFile:filePathCer1 error:&error];
    XCTAssertNotNil(savedCer1, @"Failed to initialize MscCertificate from filesystem");
    XCTAssertTrue([cer1 isEqualToMscCertificate:savedCer1], @"MscCertificate objects are not equal");
    
    MscCertificate* savedCer2 = [[MscCertificate alloc] initWithContentsOfFile:filePathCer2 error:&error];
    XCTAssertNotNil(savedCer2, @"Failed to initialize MscCertificate from filesystem");
    XCTAssertTrue([cer2 isEqualToMscCertificate:savedCer2], @"MscCertificate objects are not equal");
}

-(void)testSerializeAndDeserialize
{
    NSArray *certs = [[NSArray alloc] initWithObjects:cer1, cer2, nil];
    [NSKeyedArchiver archiveRootObject:certs toFile:filePath];
    
    NSMutableArray* savedCerts = [NSKeyedUnarchiver unarchiveObjectWithFile:filePath];
    XCTAssertEqual([savedCerts count], [certs count], @"Failed to deserialize certs");
    
    for (int i = 0; i < [certs count]; i++) {
        MscCertificate* cer = [certs objectAtIndex:i];
        MscCertificate* savedCer = [savedCerts objectAtIndex:i];
        XCTAssertTrue([cer isEqualToMscCertificate: savedCer], @"MscCertificate objects are not equal");
    }
}

-(void)testSignRequest
{
    NSError *error;
    
    [cer1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:&error];
    XCTAssertNil(error, @"Failed to sign MscCertificate");
    
    [cer2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&error];
    XCTAssertNil(error, @"Failed to sign MscCertificate");
}

@end
