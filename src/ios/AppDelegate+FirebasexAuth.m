/**
 * @file AppDelegate+FirebasexAuth.m
 * @brief Implementation of the Firebase Auth AppDelegate category.
 *
 * Handles incoming OAuth callback URLs by forwarding them to the Google Sign-In SDK.
 * This ensures that Google Sign-In OAuth redirects are properly processed when the
 * app is returned to from the authentication browser.
 */
#import "AppDelegate+FirebasexAuth.h"
#import "FirebasexAuthPlugin.h"

@import GoogleSignIn;

@implementation CDVAppDelegate (FirebasexAuth)

/**
 * Handles incoming URLs for OAuth callback processing.
 * Forwards the URL to the Google Sign-In SDK to complete the authentication flow.
 *
 * @param app     The application object.
 * @param url     The URL resource to open, typically an OAuth callback URL.
 * @param options A dictionary of URL handling options.
 * @return @c YES if the URL was handled by Google Sign-In, @c NO otherwise.
 */
- (BOOL)application:(UIApplication *)app openURL:(NSURL *)url options:(NSDictionary<UIApplicationOpenURLOptionsKey,id> *)options {
    if ([GIDSignIn.sharedInstance handleURL:url]) {
        return YES;
    }
    return NO;
}

@end
