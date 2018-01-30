//
//  Ethereum.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-25.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <secp256k1.h>
#import <secp256k1_ecdh.h>
#import <secp256k1_recovery.h>
#import <util.h>
#import <hash_impl.h>
#import <keccak-tiny.h>


#import "Transaction.h"
#import "tommath.h"
#import "Contract.h"
#import "NSNumber+BigNumber.h"
#import "RLPSerialization.h"
#import "MerkleTree.h"

@interface Ethereum : NSObject
- (void)testTransaction;
- (void)testContractCreation;
- (void)testCall:(NSString*) hexContractAddress;
-(void)testPackSolidity;

@end
