//
//  NSNumber+BigNumber.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-14.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "tommath.h"

@interface NSNumber (BigNumber)
@property (nonatomic, assign) mp_int* bigInt;

-(void)setBigIntValue:(long) value;
- (NSData *) getData;
-(NSData*) toBigIntData;

@end
