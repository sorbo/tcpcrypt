#import "TCTcpcryptController.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>

@interface TCTcpcryptController ()
- (BOOL)daemonIsRunning;
- (NSString *)daemonStatus;
- (void)refreshDaemonStatus;
- (void)checkPermissions;
@end

@implementation TCTcpcryptController

////////////////////////////////////////////////////////////////////////////////////////
#pragma mark NSObject

- (id)init {
	if ((self = [super init])) {
		_wrapperPath = [[[NSBundle mainBundle] pathForResource:@"tcpcryptd_wrapper" ofType:@""] retain];
		_tcpcryptdPath = [[[NSBundle mainBundle] pathForResource:@"tcpcryptd" ofType:@""] retain];
	}
	return self;
}

- (void)dealloc {
	[self stopDaemon:nil];
	[_wrapperPath release];
	[_tcpcryptdPath release];
	[super dealloc];
}

#pragma mark NSWindowDelegate

- (void)windowWillClose:(NSNotification *)notification {
	[self stopDaemon:nil];
	[[NSApplication sharedApplication] terminate:nil];
}

#pragma mark -

- (void)fixPermissionsForFile:(NSString *)path_ setUIDRoot:(BOOL)setUIDRoot {
	int fd, ret;
	mode_t mode;
	struct stat st;
	const char *path = [path_ cStringUsingEncoding:NSUTF8StringEncoding];
	AuthorizationRef authRef;
	OSStatus status;
	
	fd = open(path, O_NOFOLLOW);
	NSAssert(fd != -1, @"open(%s)", path);

	ret = fstat(fd, &st);
	NSAssert(ret != -1, @"fstat(%s)", path);
	
	// chmod
	mode = 0755 | S_IFREG;
	if (setUIDRoot) mode = mode | S_ISUID;
	if (st.st_mode != mode) {
		NSLog(@"%@ is 0%o, will set to 0%o", path_, st.st_mode, mode);
		if (st.st_uid == 0) {
			NSLog(@"lost perms but kept root ownership of %@", path_);
		}
		ret = fchmod(fd, mode);
		NSAssert(ret != -1, @"fchmod()");
	}
	
	// chown root
	if (st.st_uid != 0) {
		const char *args[] = {"root", path, NULL};
		status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
									 kAuthorizationFlagDefaults, &authRef);
		status = AuthorizationExecuteWithPrivileges(authRef, "/usr/sbin/chown", kAuthorizationFlagDefaults,
													  (char *const *)args, NULL);
		NSAssert(status != -1, @"chown");
	}
	
	close(fd);
}

- (void)checkPermissions {
	[self fixPermissionsForFile:_wrapperPath setUIDRoot:YES];
	[self fixPermissionsForFile:_tcpcryptdPath setUIDRoot:NO];
}

- (IBAction)startDaemon:(id)sender {
	NSLog(@"starting tcpcryptd...");
	NSAssert(![self daemonIsRunning], @"tcpcryptd already started");
	
	[self checkPermissions];
	usleep(50000); /* file perms weren't getting set? */
	_daemon = [[NSTask launchedTaskWithLaunchPath:_wrapperPath 
									   arguments:[NSArray arrayWithObject:@"start"]] retain];
	NSLog(@"started tcpcryptd, pid %u", [_daemon processIdentifier]);
	NSAssert([self daemonIsRunning], @"failed to start tcpcryptd");
	[self refreshDaemonStatus];
}

- (IBAction)stopDaemon:(id)sender {
	NSLog(@"stopping tcpcryptd...");
	
	NSTask *stopper = [NSTask launchedTaskWithLaunchPath:_wrapperPath 
											   arguments:[NSArray arrayWithObject:@"stop"]];
	
	[stopper waitUntilExit];
	NSLog(@"stopped tcpcryptd");
	NSAssert(![self daemonIsRunning], @"failed to stop tcpcryptd");
	if (_daemon) {
		[_daemon release];
		_daemon = nil;
	}
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
	[_testButton setHidden:![self daemonIsRunning]];
	[_statusLabel setStringValue:[self daemonStatus]];
}

- (IBAction)openTestPage:(id)sender {
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:@"http://tcpcrypt.org/fame.php"]];
}

@end
