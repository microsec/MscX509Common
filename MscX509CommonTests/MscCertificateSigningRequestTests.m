//
//  MscCertificateSigningRequestTests.m
//  MscX509Common
//
//  Created by Microsec on 2014.06.20..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "MscCertificateSigningRequest.h"
#import <openssl/evp.h>
#import <openssl/x509v3.h>

@interface MscCertificateSigningRequestTests : XCTestCase {
    MscCertificateSigningRequest *csr1;
    MscCertificateSigningRequest *csr2;
    NSString *filePath;
    NSString *filePathCsr1;
    NSString *filePathCsr2;
    MscRSAKey *rsaKey;
}

@end

@implementation MscCertificateSigningRequestTests

- (void)setUp
{
    [super setUp];
    
    NSError *error;
    OpenSSL_add_all_algorithms();
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    filePath = [documentsDirectory stringByAppendingPathComponent:@"requests.xml"];
    filePathCsr1 = [documentsDirectory stringByAppendingPathComponent:@"request1.csr"];
    filePathCsr2 = [documentsDirectory stringByAppendingPathComponent:@"request2.csr"];
    rsaKey = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:nil];
    
    MscX509Name *subject = [[MscX509Name alloc] init];
    subject.commonName = @"UnitTest1";
    subject.countryName = @"HU";
    subject.organizationName = @"Microsec Ltd.";
    
    csr1 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"123456" error:&error];
    XCTAssertNotNil(csr1, @"Failed to initialize MscCertificateSigningRequest");
    XCTAssertNil(error, @"MscCertificateSigningRequest initialization returned with error");
    
    subject.commonName = @"UnitTest2";
    csr2 = [[MscCertificateSigningRequest alloc] initWithSubject:subject challengePassword:@"almafa" error:&error];
    XCTAssertNotNil(csr2, @"Failed to initialize MscCertificateSigningRequest");
    XCTAssertNil(error, @"MscCertificateSigningRequest initialization returned with error");
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSaveAndLoad
{
    NSError *error;
    [csr1 saveToPath:filePathCsr1 error:&error];
    XCTAssertNil(error, @"Failed to save MscCertificateSigningRequest");
    
    [csr2 saveToPath:filePathCsr2 error:&error];
    XCTAssertNil(error, @"Failed to save MscCertificateSigningRequest");
    
    MscCertificateSigningRequest* savedCsr1 = [[MscCertificateSigningRequest alloc] initWithContentsOfFile:filePathCsr1 error:&error];
    XCTAssertNotNil(savedCsr1, @"Failed to initialize MscCertificateSigningRequest from filesystem");
    
    XCTAssertTrue([csr1 isEqualToMscCertificateSigningRequest:savedCsr1], @"MscCertificateSigningRequest objects are not equal");
    
    MscCertificateSigningRequest* savedCsr2 = [[MscCertificateSigningRequest alloc] initWithContentsOfFile:filePathCsr2 error:&error];
    XCTAssertNotNil(savedCsr2, @"Failed to initialize MscCertificateSigningRequest from filesystem");
    
    XCTAssertTrue([csr2 isEqualToMscCertificateSigningRequest:savedCsr2], @"MscCertificateSigningRequest objects are not equal");
}

-(void)testSerializeAndDeserialize
{
    NSMutableArray *csrs = [[NSMutableArray alloc] initWithObjects:csr1, csr2, nil];
    [NSKeyedArchiver archiveRootObject:csrs toFile:filePath];
    
    NSMutableArray* savedCsrs = [NSKeyedUnarchiver unarchiveObjectWithFile:filePath];
    XCTAssertEqual([savedCsrs count], [csrs count], @"Failed to deserialize csrs");
    
    for (int i = 0; i < [csrs count]; i++) {
        MscCertificateSigningRequest* csr = [csrs objectAtIndex:i];
        MscCertificateSigningRequest* savedCsr = [savedCsrs objectAtIndex:i];
        XCTAssertTrue([csr isEqualToMscCertificateSigningRequest:savedCsr], @"MscCertificateSigningRequest objects are not equal");
    }
}

-(void)testSignRequest
{
    NSError *error;
    
    [csr1 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA1 error:&error];
    XCTAssertNil(error, @"Failed to sign MscCertificateSigningRequest");
    
    [csr2 signWithRSAKey:rsaKey fingerPrintAlgorithm:FingerPrintAlgorithm_SHA256 error:&error];
    XCTAssertNil(error, @"Failed to sign MscCertificateSigningRequest");
}

@end
