#import <Cordova/CDV.h>
#import <AuthenticationServices/AuthenticationServices.h>

@import FirebaseAuth;

@interface FirebasexAuthPlugin : CDVPlugin <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>

+ (FirebasexAuthPlugin*)instance;

// Phone / MFA
- (void)verifyPhoneNumber:(CDVInvokedUrlCommand*)command;
- (void)enrollSecondAuthFactor:(CDVInvokedUrlCommand*)command;
- (void)verifySecondAuthFactor:(CDVInvokedUrlCommand*)command;
- (void)listEnrolledSecondAuthFactors:(CDVInvokedUrlCommand*)command;
- (void)unenrollSecondAuthFactor:(CDVInvokedUrlCommand*)command;

// Language
- (void)setLanguageCode:(CDVInvokedUrlCommand*)command;

// Email/Password
- (void)createUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;
- (void)signInUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;
- (void)authenticateUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command;

// Custom token & anonymous
- (void)signInUserWithCustomToken:(CDVInvokedUrlCommand*)command;
- (void)signInUserAnonymously:(CDVInvokedUrlCommand*)command;

// OAuth Providers
- (void)authenticateUserWithGoogle:(CDVInvokedUrlCommand*)command;
- (void)authenticateUserWithApple:(CDVInvokedUrlCommand*)command;
- (void)authenticateUserWithMicrosoft:(CDVInvokedUrlCommand*)command;
- (void)authenticateUserWithFacebook:(CDVInvokedUrlCommand*)command;
- (void)authenticateUserWithOAuth:(CDVInvokedUrlCommand*)command;

// Credential operations
- (void)signInWithCredential:(CDVInvokedUrlCommand*)command;
- (void)linkUserWithCredential:(CDVInvokedUrlCommand*)command;
- (void)reauthenticateWithCredential:(CDVInvokedUrlCommand*)command;
- (void)unlinkUserWithProvider:(CDVInvokedUrlCommand*)command;

// Session
- (void)isUserSignedIn:(CDVInvokedUrlCommand*)command;
- (void)signOutUser:(CDVInvokedUrlCommand*)command;
- (void)getCurrentUser:(CDVInvokedUrlCommand*)command;
- (void)reloadCurrentUser:(CDVInvokedUrlCommand*)command;

// User management
- (void)updateUserProfile:(CDVInvokedUrlCommand*)command;
- (void)updateUserEmail:(CDVInvokedUrlCommand*)command;
- (void)sendUserEmailVerification:(CDVInvokedUrlCommand*)command;
- (void)verifyBeforeUpdateEmail:(CDVInvokedUrlCommand*)command;
- (void)updateUserPassword:(CDVInvokedUrlCommand*)command;
- (void)sendUserPasswordResetEmail:(CDVInvokedUrlCommand*)command;
- (void)deleteUser:(CDVInvokedUrlCommand*)command;

// Config
- (void)useAuthEmulator:(CDVInvokedUrlCommand*)command;
- (void)getClaims:(CDVInvokedUrlCommand*)command;

// Internal helpers
- (void)handleAuthResult:(FIRAuthDataResult*)authResult error:(NSError*)error command:(CDVInvokedUrlCommand*)command;
- (NSDictionary*)createAuthErrorResult:(NSError*)error;
- (NSNumber*)saveAuthCredential:(FIRAuthCredential*)credential;
- (FIRAuthCredential*)obtainAuthCredential:(CDVInvokedUrlCommand*)command;
- (BOOL)isSignedIn;
- (BOOL)userNotSignedInError:(CDVInvokedUrlCommand*)command;

@property (nonatomic, strong) NSMutableDictionary* authCredentials;
@property (nonatomic, strong) NSString* currentNonce;
@property (nonatomic, strong) FIRMultiFactorResolver* multiFactorResolver;
@property (nonatomic, strong) FIROAuthProvider* oauthProvider;
@property (nonatomic, copy) NSString* appleSignInCallbackId;

@end
