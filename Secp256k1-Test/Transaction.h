//
//  Transaction.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2018-01-03.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "tommath.h"

typedef NS_OPTIONS(unsigned char, ChainId)  {
    ChianIdAny          = 0x00,
    ChainIdHomestead    = 0x01,
    ChainIdMorden       = 0x02,
    ChainIdRopsten      = 0x03,
    ChainIdRinkeby      = 0x04,
    ChainIdKovan        = 0x2a,
};

extern NSString * _Nullable chainName(ChainId chainId);


static NSData *stripDataZeros(NSData *data) {
    const char *bytes = data.bytes;
    NSUInteger offset = 0;
    while (offset < data.length && bytes[offset] == 0) { offset++; }
    return [data subdataWithRange:NSMakeRange(offset, data.length - offset)];
}

//hexBytes expect utf8strin encoded bytes within byte boundary
static NSData * dataFromChar(const char * chars, int len){
    
    int i = 0;
    bool flag = false;
    if(len > 1 && len %2!=0){
        flag = true;
    }
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        if(flag){
            byteChars[0] = '0';
            byteChars[1] = chars[i++];
            wholeByte = strtoul(byteChars, NULL, 16);
            [data appendBytes:&wholeByte length:1];
            flag = false;
        }
        else{
            byteChars[0] = chars[i++];
            byteChars[1] = chars[i++];
            wholeByte = strtoul(byteChars, NULL, 16);
            [data appendBytes:&wholeByte length:1];
        }
    }
    //unsigned char *bytePtr = (unsigned char *)[data bytes];
    return data;

}

static NSData *convertMPInt(mp_int i){
    uint8_t * hex;
    int size;
    //null terminated representation in ASCII char
    //https://github.com/libtom/libtommath/blob/fd81ac754af8d404b45e1dd4263457c0a1935c05/bn_mp_toradix.c
    size = mp_tohex(&i, (char*)hex);
    mp_radix_size(&i, 16, &size);
//    if(size > 2){
//        return dataFromChar([@"03E8" UTF8String], 4);
//    }

    return dataFromChar((char*)hex, size-1);
}



static NSData *dataWithByte(unsigned char value) {
    return [NSMutableData dataWithBytes:&value length:1];
}

@interface Transaction : NSObject

@property (nonatomic, assign) mp_int nonce;

@property (nonatomic,assign) mp_int gasPrice;
@property (nonatomic,assign) mp_int gasLimit;

@property (nonatomic, assign, nullable) uint8_t* toAddress;
@property (nonatomic, assign) mp_int value;
@property (nonatomic, assign, nullable) NSData* data;

@property (nonatomic, assign, nullable) char *r;
@property (nonatomic, assign, nullable) char *s;
@property (nonatomic, assign) uint8_t v;

@property (nonatomic, assign, nullable) uint8_t *fromAddress;

@property (nonatomic, assign) ChainId chainId;

- (nonnull NSData*)serialize:(bool) _signature;

- (nonnull NSData*)signSerialize;


@end
