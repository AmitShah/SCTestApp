//
//  AppDelegate.h
//  Secp256k1-Test
//
//  Created by Amit Shah on 2017-12-13.
//  Copyright © 2017 Amit Shah. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end

