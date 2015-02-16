//
//  MscRSAKeyTests.m
//  MscX509Common
//
//  Created by Microsec on 2014.06.20..
//  Copyright (c) 2014 Microsec. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "MscRSAKey.h"
#import <openssl/evp.h>


@interface MscRSAKeyTests : XCTestCase {
    MscRSAKey *rsaKey2048bit;
    MscRSAKey *rsaKey4096bit;
    NSString *filePath;
    NSString *filePath2048bit;
    NSString *filePath4096bit;
}

@end

@implementation MscRSAKeyTests

- (void)setUp
{
    [super setUp];
    
    OpenSSL_add_all_algorithms();
    
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];
    filePath = [documentsDirectory stringByAppendingPathComponent:@"keys.xml"];
    filePath2048bit = [documentsDirectory stringByAppendingPathComponent:@"rsa2048.key"];
    filePath4096bit = [documentsDirectory stringByAppendingPathComponent:@"rsa4096.key"];
    
    NSError *error;
    rsaKey2048bit = [[MscRSAKey alloc] initWithKeySize:KeySize_2048 error:&error];
    XCTAssertNotNil(rsaKey2048bit, @"Failed to initialize MscRSAKey");
    XCTAssertNil(error, @"MscRSAKey initialization returned with error");
    
    rsaKey4096bit = [[MscRSAKey alloc] initWithKeySize:KeySize_4096 error:&error];
    XCTAssertNotNil(rsaKey4096bit, @"Failed to initialize MscRSAKey");
    XCTAssertNil(error, @"MscRSAKey initialization returned with error");
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testSaveAndLoad
{
    NSError *error;
    [rsaKey2048bit saveToPath:filePath2048bit error:&error];
    XCTAssertNil(error, @"Failed to save MscRSAKey");
    
    [rsaKey4096bit saveToPath:filePath4096bit error:&error];
    XCTAssertNil(error, @"Failed to save MscRSAKey");
    
    MscRSAKey* savedRSAKey2048bit = [[MscRSAKey alloc] initWithContentsOfFile:filePath2048bit error:&error];
    XCTAssertNotNil(savedRSAKey2048bit, @"Failed to initialize MscRSAKey from filesystem");
    XCTAssertTrue([rsaKey2048bit isEqualToMscRSA:savedRSAKey2048bit], @"MscRSAKey objects are not equal");

    MscRSAKey* savedRSAKey4096bit = [[MscRSAKey alloc] initWithContentsOfFile:filePath4096bit error:&error];
    XCTAssertNotNil(savedRSAKey4096bit, @"Failed to initialize MscRSAKey from filesystem");
    XCTAssertTrue([rsaKey4096bit isEqualToMscRSA:savedRSAKey4096bit], @"MscRSAKey objects are not equal");
}

-(void)testSign {
    
    MscX509CommonError* signError;
    NSString* data = @"60d33ebbf3bc83a27814af22e5b0604088a635e5da0995f749289bf11d0edcea";
    NSData* d = [[NSData alloc] initWithBase64EncodedString:data options:0];
    
    NSData* signedData = [rsaKey2048bit signHash:d error:&signError];
    XCTAssertNil(signError, @"Failed to sign hash");
    XCTAssertNotNil(signedData, @"SignedData is empty");
}

-(void)testSerializeAndDeserialize
{
    NSArray *rsaKeys = [[NSArray alloc] initWithObjects:rsaKey2048bit, rsaKey4096bit, nil];
    [NSKeyedArchiver archiveRootObject:rsaKeys toFile:filePath];
    
    NSMutableArray* savedRSAKeys = [NSKeyedUnarchiver unarchiveObjectWithFile:filePath];
    XCTAssertEqual([savedRSAKeys count], [rsaKeys count], @"Failed to deserialize rsaKeys");
    
    for (int i = 0; i < [rsaKeys count]; i++) {
        MscRSAKey* key = [rsaKeys objectAtIndex:i];
        MscRSAKey* savedKey = [savedRSAKeys objectAtIndex:i];
        XCTAssertTrue([key isEqualToMscRSA:savedKey], @"MscRSAKey objects are not equal");
    }
}

@end
