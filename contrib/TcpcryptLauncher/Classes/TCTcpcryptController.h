#import <Cocoa/Cocoa.h>


@interface TCTcpcryptController : NSObject <NSWindowDelegate> {
	NSString* _wrapperPath;
	NSString* _tcpcryptdPath;
	NSTask* _daemon;
	NSPipe* _pipe;
	
	IBOutlet NSButton* _startButton;
	IBOutlet NSButton* _stopButton;
	IBOutlet NSTextField* _statusLabel;
	IBOutlet NSButton* _testButton;
}

- (IBAction)startDaemon:(id)sender;
- (IBAction)stopDaemon:(id)sender;
- (IBAction)openTestPage:(id)sender;

@end
