#import "TCTcpcryptController.h"
#include <sys/stat.h>
#include <string.h>

@interface TCTcpcryptController ()
- (BOOL)daemonIsRunning;
- (NSString *)daemonStatus;
- (void)refreshDaemonStatus;
- (void)setSuidRoot;
@end

@implementation TCTcpcryptController

////////////////////////////////////////////////////////////////////////////////////////
#pragma mark NSObject

- (id)init {
	if (self = [super init]) {
		_launchPath = [[[NSBundle mainBundle] pathForResource:@"launch_tcpcryptd" ofType:@""] retain];
	}
	return self;
}

- (void)dealloc {
	if ([self daemonIsRunning]) {
		[self stopDaemon:nil];
	}
	[_launchPath release];
	[super dealloc];
}

#pragma mark NSWindowDelegate

- (void)windowDidBecomeMain:(NSNotification *)notification {
	[self refreshDaemonStatus];
}

#pragma mark -

- (void)setSuidRoot {
	char *cLaunchPath = (char *)[_launchPath cStringUsingEncoding:NSUTF8StringEncoding];
	
	if (chmod(cLaunchPath, 04755) != 0) {
		NSLog(@"chmod failed, assume it's because it belongs to root");
		return;
	}
	
	const char *launchPath = "/usr/sbin/chown";
	char *args[] = {"root", cLaunchPath, NULL};
	
	AuthorizationRef authRef;
	OSStatus status;
	status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
								 kAuthorizationFlagDefaults, &authRef);
	status = AuthorizationExecuteWithPrivileges(authRef, launchPath, kAuthorizationFlagDefaults,
												args, NULL);
	NSLog(@"chmod $? = %d", status);
	if (status) {
		NSLog(@"chmod $? = %d, %s", status, strerror(status));
	}
	
}

- (IBAction)startDaemon:(id)sender {
	NSLog(@"starting tcpcryptd...");
	NSAssert(![self daemonIsRunning], @"tcpcryptd already started");
	
	[self setSuidRoot];
	_daemon = [[NSTask alloc] init];
	_daemon.launchPath = _launchPath;
		
	_pipe = [NSPipe pipe];
	//[_daemon setStandardOutput:_pipe];
	//NSFileHandle *daemonOut = [_pipe fileHandleForReading];
	[_daemon setStandardInput:[NSPipe pipe]];
	
	[_daemon launch];
	
	//NSData *data;
    //data = [daemonOut readDataToEndOfFile];
	
    //NSString *string;
    //string = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
    //NSLog (@"woop!  got\n%@", string);

	NSLog(@"started tcpcryptd");
	NSAssert([self daemonIsRunning], @"failed to start tcpcryptd");
	[self refreshDaemonStatus];
}

- (IBAction)stopDaemon:(id)sender {
	NSLog(@"stopping tcpcryptd...");
	[_daemon interrupt];
	NSLog(@"sent SIGINT");
	[_daemon waitUntilExit];
	NSLog(@"stopped tcpcryptd");
	NSAssert(![self daemonIsRunning], @"failed to stop tcpcryptd");
	[_daemon release];
	_daemon = nil;
	[self refreshDaemonStatus];
}

- (BOOL)daemonIsRunning {
	return _daemon && [_daemon isRunning];
}

- (NSString *)daemonStatus {
	return [self daemonIsRunning] ? @"Tcpcrypt is running on ports 80 (http) and 7777." :
								    @"Tcpcrypt is off.";
}

- (void)refreshDaemonStatus {
	[_startButton setHidden:[self daemonIsRunning]];
	[_stopButton setHidden:![self daemonIsRunning]];
	[_statusLabel setStringValue:[self daemonStatus]];
}

@end
