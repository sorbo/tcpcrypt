//
//  TcpcryptLauncherAppDelegate.m
//  TcpcryptLauncher
//
//  Created by Samuel Quinn Slack on 8/17/10.
//  Copyright (c) 2010 __MyCompanyName__. All rights reserved.
//


#import "TcpcryptLauncherAppDelegate.h"

#include "../../../user/src/tcpcrypt_version.h"

@implementation TcpcryptLauncherAppDelegate

@synthesize window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    NSString* title = [NSString stringWithFormat:@"tcpcrypt v%s" ,
    						 TCPCRYPT_VERSION];

    [title autorelease];
    [[self window] setTitle:title];
    // Insert code here to initialize your application
}

@end

