#import <Cocoa/Cocoa.h>


@interface TCTcpcryptController : NSObject <NSWindowDelegate> {
	NSString* _launchPath;
	NSTask* _daemon;
	NSPipe* _pipe;
	
	IBOutlet NSButton* _startButton;
	IBOutlet NSButton* _stopButton;
	IBOutlet NSTextField* _statusLabel;
}

- (IBAction)startDaemon:(id)sender;
- (IBAction)stopDaemon:(id)sender;

@end
