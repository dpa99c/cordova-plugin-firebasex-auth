#import "AppDelegate+FirebasexAuth.h"
#import "FirebasexAuthPlugin.h"

@import GoogleSignIn;

@implementation AppDelegate (FirebasexAuth)

// Google Sign-In URL handling for older iOS versions or non-scene-based apps
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([GIDSignIn.sharedInstance handleURL:url]) {
        return YES;
    }
    return NO;
}

@end
