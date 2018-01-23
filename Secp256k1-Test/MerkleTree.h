//
//  MerkleTree.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-22.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface MerkleTree : NSObject

//an ordered list of leaf elements
@property NSArray* leafNodes;

@property NSMutableArray* levels;

@property int treeHeight;


-(nonnull id) init: (NSArray*) _leafNodes;

//generate a merkle proof for the element
//the element is keccack256 encoded, we send back a list of hops to the root
-(nonnull NSArray*) generateProof:(nonnull NSData*) element withRoot:(nullable NSData*) root;

-(void) calculateRoot;

-(void) printMerkleTree;


@end
