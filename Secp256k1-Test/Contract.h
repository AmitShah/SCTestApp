//
//  Contract+Contract.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-04.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Contract:NSObject
    @property NSMutableArray *property;


-(NSData*) encodeSingle: (NSString*) type withArg:(id) arg;
-(NSData *) rawEncode: (NSArray*) types withVals: (NSArray*) values;

@end
