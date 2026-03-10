/**
 * @file FirebasexAuthPlugin.h
 * @brief Cordova plugin header for Firebase Authentication on iOS.
 *
 * Declares the @c FirebasexAuthPlugin class which provides comprehensive Firebase Authentication
 * functionality including email/password, phone number, anonymous sign-in, custom tokens,
 * and OAuth providers (Google, Apple, Microsoft, Facebook, generic OAuth). Also supports
 * multi-factor authentication (MFA), credential management, user profile operations,
 * and auth state change listeners.
 */
#import <Cordova/CDV.h>
#import <AuthenticationServices/AuthenticationServices.h>

@import FirebaseAuth;

/**
 * @brief Cordova plugin providing Firebase Authentication functionality on iOS.
 *
 * Implements @c ASAuthorizationControllerDelegate for Apple Sign-In and
 * @c ASAuthorizationControllerPresentationContextProviding for presenting the Apple Sign-In UI.
 * Manages native auth credentials, OAuth providers, and multi-factor authentication state.
 */
@interface FirebasexAuthPlugin : CDVPlugin <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>

/**
 * Returns the singleton instance of this plugin.
 * @return The plugin instance, or nil if not yet initialized.
 */
+ (FirebasexAuthPlugin*)instance;

// Phone / MFA

/** Verifies a phone number for phone-based authentication. */
- (void)verifyPhoneNumber:(CDVInvokedUrlCommand*)command;
/** Enrolls a phone number as a second authentication factor for the current user. */
- (void)enrollSecondAuthFactor:(CDVInvokedUrlCommand*)command;
/** Verifies a second authentication factor during an MFA challenge or enrollment. */
- (void)verifySecondAuthFactor:(CDVInvokedUrlCommand*)command;
/** Lists the second authentication factors enrolled for the current user. */
- (void)listEnrolledSecondAuthFactors:(CDVInvokedUrlCommand*)command;
/** Removes an enrolled second authentication factor from the current user. */
- (void)unenrollSecondAuthFactor:(CDVInvokedUrlCommand*)command;

// Language

/** Sets the language code for Firebase Auth operations (e.g. SMS verification messages). */
- (void)setLanguageCode:(CDVInvokedUrlCommand*)command;

// Email/Password

/** Creates a new user account with email and password. */
- (void)createUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;
/** Signs in an existing user with email and password. */
- (void)signInUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;
/** Creates an email/password credential without signing in. */
- (void)authenticateUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;

// Custom token & anonymous

/** Signs in a user with a custom token from the Firebase Admin SDK. */
- (void)signInUserWithCustomToken:(CDVInvokedUrlCommand*)command;
/** Signs in the user anonymously. */
- (void)signInUserAnonymously:(CDVInvokedUrlCommand*)command;

// OAuth Providers

/** Authenticates with Google Sign-In using the Google Sign-In SDK. */
- (void)authenticateUserWithGoogle:(CDVInvokedUrlCommand*)command;
/** Authenticates with Apple Sign-In using ASAuthorizationController. */
- (void)authenticateUserWithApple:(CDVInvokedUrlCommand*)command;
/** Authenticates with Microsoft via Firebase OAuthProvider. */
- (void)authenticateUserWithMicrosoft:(CDVInvokedUrlCommand*)command;
/** Authenticates with Facebook using a pre-obtained access token. */
- (void)authenticateUserWithFacebook:(CDVInvokedUrlCommand*)command;
/** Authenticates with a generic OAuth provider via Firebase OAuthProvider. */
- (void)authenticateUserWithOAuth:(CDVInvokedUrlCommand*)command;

// Credential operations

/** Signs in the user using a previously stored native credential. */
- (void)signInWithCredential:(CDVInvokedUrlCommand*)command;
/** Links a credential to the currently signed-in user. */
- (void)linkUserWithCredential:(CDVInvokedUrlCommand*)command;
/** Re-authenticates the current user with a fresh credential. */
- (void)reauthenticateWithCredential:(CDVInvokedUrlCommand*)command;
/** Unlinks a provider from the currently signed-in user. */
- (void)unlinkUserWithProvider:(CDVInvokedUrlCommand*)command;

// Session

/** Checks whether a user is currently signed in. */
- (void)isUserSignedIn:(CDVInvokedUrlCommand*)command;
/** Signs out the currently authenticated user. */
- (void)signOutUser:(CDVInvokedUrlCommand*)command;
/** Gets the profile information for the currently signed-in user. */
- (void)getCurrentUser:(CDVInvokedUrlCommand*)command;
/** Reloads the current user's profile from the server. */
- (void)reloadCurrentUser:(CDVInvokedUrlCommand*)command;

// User management

/** Updates the current user's display name and/or photo URL. */
- (void)updateUserProfile:(CDVInvokedUrlCommand*)command;
/** Updates the current user's email address (sends verification first). */
- (void)updateUserEmail:(CDVInvokedUrlCommand*)command;
/** Sends an email verification to the current user's email address. */
- (void)sendUserEmailVerification:(CDVInvokedUrlCommand*)command;
/** Sends a verification email before updating to a new email address. */
- (void)verifyBeforeUpdateEmail:(CDVInvokedUrlCommand*)command;
/** Updates the current user's password. */
- (void)updateUserPassword:(CDVInvokedUrlCommand*)command;
/** Sends a password reset email to the specified email address. */
- (void)sendUserPasswordResetEmail:(CDVInvokedUrlCommand*)command;
/** Deletes the currently signed-in user account. */
- (void)deleteUser:(CDVInvokedUrlCommand*)command;

// Config

/** Configures Firebase Auth to connect to a local Auth emulator for testing. */
- (void)useAuthEmulator:(CDVInvokedUrlCommand*)command;
/** Retrieves the custom claims from the current user's ID token. */
- (void)getClaims:(CDVInvokedUrlCommand*)command;

// Internal helpers

/**
 * Handles the result of a Firebase Auth operation.
 * Detects MFA challenges, credential conflicts, and standard auth errors.
 * @param authResult The auth data result, or nil on failure.
 * @param error      The error, or nil on success.
 * @param command    The Cordova command to send results to.
 */
- (void)handleAuthResult:(FIRAuthDataResult*)authResult error:(NSError*)error command:(CDVInvokedUrlCommand*)command;

/**
 * Creates a Cordova error plugin result from an auth error.
 * Handles MFA challenges (FIRAuthErrorCodeSecondFactorRequired) and
 * credential-already-in-use errors (FIRAuthErrorCodeCredentialAlreadyInUse).
 * @param error The auth error.
 * @return A CDVPluginResult with error status.
 */
- (CDVPluginResult*)createAuthErrorResult:(NSError*)error;

/**
 * Stores an auth credential and returns its numeric key for later retrieval.
 * @param credential The Firebase auth credential to store.
 * @return The generated numeric key.
 */
- (NSNumber*)saveAuthCredential:(FIRAuthCredential*)credential;

/**
 * Retrieves an auth credential from stored credentials or constructs one from arguments.
 * Supports credential lookup by ID or phone verification ID/code pair.
 * @param command The Cordova command with credential arguments.
 * @return The resolved auth credential, or nil if not found.
 */
- (FIRAuthCredential*)obtainAuthCredential:(CDVInvokedUrlCommand*)command;

/**
 * Checks whether any user is currently signed in.
 * @return YES if a user is signed in, NO otherwise.
 */
- (BOOL)isSignedIn;

/**
 * Checks whether a user is signed in and sends an error if not.
 * @param command The Cordova command to send the error to.
 * @return YES if no user is signed in (error was sent), NO if a user is signed in.
 */
- (BOOL)userNotSignedInError:(CDVInvokedUrlCommand*)command;

/** Map of stored auth credentials keyed by numeric IDs for passing between JS and native. */
@property (nonatomic, strong) NSMutableDictionary* authCredentials;
/** The current cryptographic nonce used for Apple Sign-In to prevent replay attacks. */
@property (nonatomic, strong) NSString* currentNonce;
/** Resolver for multi-factor authentication challenges. Set when an MFA challenge is triggered. */
@property (nonatomic, strong) FIRMultiFactorResolver* multiFactorResolver;
/** The current OAuth provider instance for pending OAuth flows (Microsoft, generic OAuth). */
@property (nonatomic, strong) FIROAuthProvider* oauthProvider;
/** The callback ID for the pending Apple Sign-In operation. */
@property (nonatomic, copy) NSString* appleSignInCallbackId;

@end
