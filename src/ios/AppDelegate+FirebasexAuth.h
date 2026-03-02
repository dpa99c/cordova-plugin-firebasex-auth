/**
 * @file AppDelegate+FirebasexAuth.h
 * @brief AppDelegate category for Firebase Authentication URL handling.
 *
 * Adds Google Sign-In URL handling to the app delegate for OAuth callback URLs.
 * This category intercepts incoming URLs and forwards them to the Google Sign-In SDK
 * for processing OAuth redirect URLs.
 */
#import <UIKit/UIKit.h>
#import "AppDelegate.h"

/**
 * @brief AppDelegate category that integrates Firebase Auth URL handling.
 *
 * Implements the @c application:openURL:options: method to handle OAuth callback URLs
 * from Google Sign-In. This is required for the Google Sign-In flow on iOS for
 * non-scene-based apps or older iOS versions.
 */
@interface AppDelegate (FirebasexAuth)
@end
