#import "FirebasexAuthPlugin.h"
#import "FirebasexCorePlugin.h"
#import <CommonCrypto/CommonDigest.h>

@import FirebaseAuth;
@import GoogleSignIn;

static FirebasexAuthPlugin* authPluginInstance;

@implementation FirebasexAuthPlugin

+ (FirebasexAuthPlugin*)instance {
    return authPluginInstance;
}

- (void)pluginInitialize {
    authPluginInstance = self;
    self.authCredentials = [NSMutableDictionary dictionary];

    @try {
        [[FIRAuth auth] addAuthStateDidChangeListener:^(FIRAuth * _Nonnull auth, FIRUser * _Nullable user) {
            BOOL isSignedIn = user != nil;
            NSString* js = [NSString stringWithFormat:@"if(typeof(FirebasexAuth) !== 'undefined' && typeof(FirebasexAuth._onAuthStateChange) === 'function'){FirebasexAuth._onAuthStateChange(%@)}", isSignedIn ? @"true": @"false"];
            FirebasexCorePlugin* core = [FirebasexCorePlugin sharedInstance];
            if (core) {
                [core executeGlobalJavascript:js];
            }
        }];

        [[FIRAuth auth] addIDTokenDidChangeListener:^(FIRAuth * _Nonnull auth, FIRUser * _Nullable user) {
            BOOL isSignedIn = user != nil;
            NSString* js = [NSString stringWithFormat:@"if(typeof(FirebasexAuth) !== 'undefined' && typeof(FirebasexAuth._onAuthIdTokenChange) === 'function'){FirebasexAuth._onAuthIdTokenChange(%@)}", isSignedIn ? @"true": @"false"];
            FirebasexCorePlugin* core = [FirebasexCorePlugin sharedInstance];
            if (core) {
                [core executeGlobalJavascript:js];
            }
        }];
    } @catch (NSException *exception) {
        NSLog(@"[FirebasexAuth] Error registering auth listeners: %@", exception);
    }
}

#pragma mark - Phone / MFA

- (void)verifyPhoneNumber:(CDVInvokedUrlCommand*)command {
    NSString* phoneNumber = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRPhoneAuthProvider provider] verifyPhoneNumber:phoneNumber UIDelegate:nil completion:^(NSString* _Nullable verificationID, NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    NSMutableDictionary* result = [NSMutableDictionary dictionary];
                    result[@"verificationId"] = verificationID;
                    result[@"instantVerification"] = @NO;
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
                    [pluginResult setKeepCallbackAsBool:YES];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)enrollSecondAuthFactor:(CDVInvokedUrlCommand*)command {
    NSString* phoneNumber = [command.arguments objectAtIndex:0];
    NSString* displayName = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            FIRUser* user = [FIRAuth auth].currentUser;
            if (!user) {
                [self sendErrorMessage:@"No user is currently signed in" command:command];
                return;
            }
            [user.multiFactor getSessionWithCompletion:^(FIRMultiFactorSession* _Nullable session, NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                    return;
                }
                [FIRPhoneAuthProvider.provider verifyPhoneNumber:phoneNumber UIDelegate:nil multiFactorSession:session completion:^(NSString* _Nullable verificationID, NSError* _Nullable error) {
                    if (error) {
                        [self sendErrorResult:error command:command];
                    } else {
                        NSMutableDictionary* result = [NSMutableDictionary dictionary];
                        result[@"verificationId"] = verificationID;
                        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
                        [pluginResult setKeepCallbackAsBool:YES];
                        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                    }
                }];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)verifySecondAuthFactor:(CDVInvokedUrlCommand*)command {
    NSString* verificationId = [command.arguments objectAtIndex:0];
    NSString* code = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            FIRPhoneAuthCredential* credential = [[FIRPhoneAuthProvider provider] credentialWithVerificationID:verificationId verificationCode:code];
            FIRMultiFactorAssertion* assertion = [FIRPhoneMultiFactorGenerator assertionWithCredential:credential];

            if (self.multiFactorResolver) {
                [self.multiFactorResolver resolveSignInWithAssertion:assertion completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                    self.multiFactorResolver = nil;
                    [self handleAuthResult:authResult error:error command:command];
                }];
            } else {
                FIRUser* user = [FIRAuth auth].currentUser;
                if (user) {
                    [user.multiFactor enrollWithAssertion:assertion displayName:nil completion:^(NSError* _Nullable error) {
                        if (error) {
                            [self sendErrorResult:error command:command];
                        } else {
                            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                        }
                    }];
                } else {
                    [self sendErrorMessage:@"No user is currently signed in" command:command];
                }
            }
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)listEnrolledSecondAuthFactors:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            FIRUser* user = [FIRAuth auth].currentUser;
            if (!user) {
                [self sendErrorMessage:@"No user is currently signed in" command:command];
                return;
            }

            NSArray<FIRMultiFactorInfo*>* enrolledFactors = user.multiFactor.enrolledFactors;
            NSMutableArray* result = [NSMutableArray array];
            for (FIRMultiFactorInfo* factorInfo in enrolledFactors) {
                NSMutableDictionary* factor = [NSMutableDictionary dictionary];
                factor[@"displayName"] = factorInfo.displayName ?: [NSNull null];
                factor[@"factorId"] = factorInfo.factorID;
                if ([factorInfo isKindOfClass:[FIRPhoneMultiFactorInfo class]]) {
                    FIRPhoneMultiFactorInfo* phoneInfo = (FIRPhoneMultiFactorInfo*)factorInfo;
                    factor[@"phoneNumber"] = phoneInfo.phoneNumber;
                }
                [result addObject:factor];
            }
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsArray:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)unenrollSecondAuthFactor:(CDVInvokedUrlCommand*)command {
    NSNumber* selectedIndex = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            FIRUser* user = [FIRAuth auth].currentUser;
            if (!user) {
                [self sendErrorMessage:@"No user is currently signed in" command:command];
                return;
            }

            NSArray<FIRMultiFactorInfo*>* enrolledFactors = user.multiFactor.enrolledFactors;
            NSInteger idx = [selectedIndex integerValue];
            if (idx < 0 || idx >= (NSInteger)enrolledFactors.count) {
                [self sendErrorMessage:@"Invalid factor index" command:command];
                return;
            }

            FIRMultiFactorInfo* selectedFactor = enrolledFactors[idx];
            [user.multiFactor unenrollWithInfo:selectedFactor completion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Language

- (void)setLanguageCode:(CDVInvokedUrlCommand*)command {
    NSString* lang = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            [FIRAuth auth].languageCode = lang;
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Email/Password

- (void)createUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    NSString* password = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] createUserWithEmail:email password:password completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)signInUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    NSString* password = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] signInWithEmail:email password:password completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)authenticateUserWithEmailAndPassword:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    NSString* password = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            FIRAuthCredential* credential = [FIREmailAuthProvider credentialWithEmail:email password:password];
            NSNumber* key = [self saveAuthCredential:credential];
            NSDictionary* result = @{@"key": key};
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Custom token & anonymous

- (void)signInUserWithCustomToken:(CDVInvokedUrlCommand*)command {
    NSString* customToken = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] signInWithCustomToken:customToken completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)signInUserAnonymously:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] signInAnonymouslyWithCompletion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - OAuth Providers

- (void)authenticateUserWithGoogle:(CDVInvokedUrlCommand*)command {
    NSString* clientId = [command.arguments objectAtIndex:0];
    BOOL signIn = YES;
    if (command.arguments.count > 1 && ![[command.arguments objectAtIndex:1] isEqual:[NSNull null]]) {
        NSDictionary* options = [command.arguments objectAtIndex:1];
        if (options[@"signIn"]) {
            signIn = [options[@"signIn"] boolValue];
        }
    }

    @try {
        GIDConfiguration* config = [[GIDConfiguration alloc] initWithClientID:clientId];
        GIDSignIn.sharedInstance.configuration = config;

        dispatch_async(dispatch_get_main_queue(), ^{
            [GIDSignIn.sharedInstance signInWithPresentingViewController:self.viewController completion:^(GIDSignInResult* _Nullable result, NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                    return;
                }

                GIDGoogleUser* user = result.user;
                FIRAuthCredential* credential = [FIRGoogleAuthProvider credentialWithIDToken:user.idToken.tokenString accessToken:user.accessToken.tokenString];

                if (signIn) {
                    [[FIRAuth auth] signInWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                        [self handleAuthResult:authResult error:error command:command];
                    }];
                } else {
                    NSNumber* key = [self saveAuthCredential:credential];
                    NSMutableDictionary* returnResult = [NSMutableDictionary dictionary];
                    returnResult[@"key"] = key;
                    returnResult[@"idToken"] = user.idToken.tokenString;
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:returnResult];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        });
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (void)authenticateUserWithApple:(CDVInvokedUrlCommand*)command {
    @try {
        self.appleSignInCallbackId = command.callbackId;
        [self startSignInWithAppleFlow];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (void)authenticateUserWithMicrosoft:(CDVInvokedUrlCommand*)command {
    [self authenticateWithOAuth:@"microsoft.com" command:command];
}

- (void)authenticateUserWithFacebook:(CDVInvokedUrlCommand*)command {
    NSString* accessToken = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            FIRAuthCredential* credential = [FIRFacebookAuthProvider credentialWithAccessToken:accessToken];
            [[FIRAuth auth] signInWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)authenticateUserWithOAuth:(CDVInvokedUrlCommand*)command {
    NSString* providerId = [command.arguments objectAtIndex:0];
    NSDictionary* options = nil;
    if (command.arguments.count > 1 && ![[command.arguments objectAtIndex:1] isEqual:[NSNull null]]) {
        options = [command.arguments objectAtIndex:1];
    }

    NSMutableDictionary* customParameters = nil;
    NSArray* scopes = nil;
    if (options) {
        customParameters = [NSMutableDictionary dictionaryWithDictionary:options[@"customParameters"] ?: @{}];
        scopes = options[@"scopes"];
    }

    [self authenticateWithOAuth:providerId customParameters:customParameters scopes:scopes command:command];
}

- (void)authenticateWithOAuth:(NSString*)providerId command:(CDVInvokedUrlCommand*)command {
    NSMutableDictionary* customParameters = nil;
    if (command.arguments.count > 0 && ![[command.arguments objectAtIndex:0] isEqual:[NSNull null]]) {
        // First arg for Apple/Microsoft is locale
        NSString* locale = [command.arguments objectAtIndex:0];
        customParameters = [NSMutableDictionary dictionary];
        customParameters[@"locale"] = locale;
    }
    [self authenticateWithOAuth:providerId customParameters:customParameters scopes:nil command:command];
}

- (void)authenticateWithOAuth:(NSString*)providerId customParameters:(NSDictionary*)customParameters scopes:(NSArray*)scopes command:(CDVInvokedUrlCommand*)command {
    @try {
        self.oauthProvider = [FIROAuthProvider providerWithProviderID:providerId];
        if (customParameters) {
            [self.oauthProvider setCustomParameters:customParameters];
        }
        if (scopes) {
            [self.oauthProvider setScopes:scopes];
        }

        [self.oauthProvider getCredentialWithUIDelegate:nil completion:^(FIRAuthCredential* _Nullable credential, NSError* _Nullable error) {
            if (error) {
                [self sendErrorResult:error command:command];
                return;
            }
            [[FIRAuth auth] signInWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        }];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

#pragma mark - Apple Sign-In Flow

- (void)startSignInWithAppleFlow {
    NSString* nonce = [self randomNonce:32];
    self.currentNonce = nonce;

    ASAuthorizationAppleIDProvider* appleIDProvider = [[ASAuthorizationAppleIDProvider alloc] init];
    ASAuthorizationAppleIDRequest* request = [appleIDProvider createRequest];
    request.requestedScopes = @[ASAuthorizationScopeFullName, ASAuthorizationScopeEmail];
    request.nonce = [self stringBySha256HashingString:nonce];

    ASAuthorizationController* authorizationController = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
    authorizationController.delegate = self;
    authorizationController.presentationContextProvider = self;
    [authorizationController performRequests];
}

- (NSString*)stringBySha256HashingString:(NSString*)input {
    const char* string = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(string, (CC_LONG)strlen(string), result);

    NSMutableString* hashed = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashed appendFormat:@"%02x", result[i]];
    }
    return hashed;
}

- (NSString*)randomNonce:(NSInteger)length {
    NSAssert(length > 0, @"Expected nonce to have positive length");
    NSString* charset = @"0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._";
    NSMutableString* result = [NSMutableString stringWithCapacity:length];
    NSInteger remainingLength = length;

    while (remainingLength > 0) {
        NSMutableArray* randoms = [NSMutableArray arrayWithCapacity:16];
        for (NSInteger i = 0; i < 16; i++) {
            uint8_t random = 0;
            int errorCode = SecRandomCopyBytes(kSecRandomDefault, 1, &random);
            if (errorCode != errSecSuccess) {
                return nil;
            }
            [randoms addObject:@(random)];
        }

        for (NSNumber* random in randoms) {
            if (remainingLength == 0) break;
            if ([random unsignedIntValue] < charset.length) {
                [result appendFormat:@"%C", [charset characterAtIndex:[random unsignedIntValue]]];
                remainingLength--;
            }
        }
    }
    return result;
}

#pragma mark - ASAuthorizationControllerDelegate

- (void)authorizationController:(ASAuthorizationController*)controller didCompleteWithAuthorization:(ASAuthorization*)authorization {
    if ([authorization.credential isKindOfClass:[ASAuthorizationAppleIDCredential class]]) {
        ASAuthorizationAppleIDCredential* appleIDCredential = (ASAuthorizationAppleIDCredential*)authorization.credential;
        NSString* rawNonce = self.currentNonce;
        if (!rawNonce) {
            NSLog(@"[FirebasexAuth] Invalid state: A login callback was received, but no login request was sent.");
            return;
        }

        NSData* appleIDToken = appleIDCredential.identityToken;
        if (!appleIDToken) {
            NSLog(@"[FirebasexAuth] Unable to fetch identity token");
            return;
        }

        NSString* idToken = [[NSString alloc] initWithData:appleIDToken encoding:NSUTF8StringEncoding];
        if (!idToken) {
            NSLog(@"[FirebasexAuth] Unable to serialize token string from data");
            return;
        }

        FIROAuthCredential* credential = (FIROAuthCredential*)[FIROAuthProvider credentialWithProviderID:@"apple.com" IDToken:idToken rawNonce:rawNonce];
        NSNumber* key = [self saveAuthCredential:credential];

        NSMutableDictionary* result = [NSMutableDictionary dictionary];
        result[@"key"] = key;
        result[@"idToken"] = idToken;
        result[@"rawNonce"] = rawNonce;
        if (appleIDCredential.fullName.givenName) {
            result[@"givenName"] = appleIDCredential.fullName.givenName;
        }
        if (appleIDCredential.fullName.familyName) {
            result[@"familyName"] = appleIDCredential.fullName.familyName;
        }

        if (self.appleSignInCallbackId) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:self.appleSignInCallbackId];
            self.appleSignInCallbackId = nil;
        }
    }
}

- (void)authorizationController:(ASAuthorizationController*)controller didCompleteWithError:(NSError*)error {
    NSLog(@"[FirebasexAuth] Apple Sign in failed: %@", error.localizedDescription);
    if (self.appleSignInCallbackId) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:error.localizedDescription];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:self.appleSignInCallbackId];
        self.appleSignInCallbackId = nil;
    }
}

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController*)controller {
    return self.viewController.view.window;
}

#pragma mark - Credential operations

- (void)signInWithCredential:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            FIRAuthCredential* credential = [self obtainAuthCredential:command];
            if (!credential) {
                [self sendErrorMessage:@"Failed to obtain auth credential from provided arguments" command:command];
                return;
            }
            [[FIRAuth auth] signInWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)linkUserWithCredential:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRAuthCredential* credential = [self obtainAuthCredential:command];
            if (!credential) {
                [self sendErrorMessage:@"Failed to obtain auth credential from provided arguments" command:command];
                return;
            }
            FIRUser* user = [FIRAuth auth].currentUser;
            [user linkWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)reauthenticateWithCredential:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRAuthCredential* credential = [self obtainAuthCredential:command];
            if (!credential) {
                [self sendErrorMessage:@"Failed to obtain auth credential from provided arguments" command:command];
                return;
            }
            FIRUser* user = [FIRAuth auth].currentUser;
            [user reauthenticateWithCredential:credential completion:^(FIRAuthDataResult* _Nullable authResult, NSError* _Nullable error) {
                [self handleAuthResult:authResult error:error command:command];
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)unlinkUserWithProvider:(CDVInvokedUrlCommand*)command {
    NSString* providerId = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user unlinkFromProvider:providerId completion:^(FIRUser* _Nullable updatedUser, NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Session

- (void)isUserSignedIn:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            BOOL signedIn = [self isSignedIn];
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:signedIn];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)signOutUser:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            NSError* error;
            [[FIRAuth auth] signOut:&error];
            if (error) {
                [self sendErrorResult:error command:command];
            } else {
                CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            }
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - User Info

- (void)getCurrentUser:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [self extractAndReturnUserInfo:user command:command];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)reloadCurrentUser:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user reloadWithCompletion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    FIRUser* reloadedUser = [FIRAuth auth].currentUser;
                    if (reloadedUser) {
                        [self extractAndReturnUserInfo:reloadedUser command:command];
                    } else {
                        [self sendErrorMessage:@"User not found after reload" command:command];
                    }
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)extractAndReturnUserInfo:(FIRUser*)user command:(CDVInvokedUrlCommand*)command {
    [user getIDTokenResultWithCompletion:^(FIRAuthTokenResult* _Nullable tokenResult, NSError* _Nullable error) {
        NSMutableDictionary* result = [NSMutableDictionary dictionary];

        if (tokenResult) {
            result[@"idToken"] = tokenResult.token ?: [NSNull null];
            result[@"claims"] = tokenResult.claims ?: @{};
        }

        result[@"name"] = user.displayName ?: [NSNull null];
        result[@"email"] = user.email ?: [NSNull null];
        result[@"emailIsVerified"] = @(user.emailVerified);
        result[@"phoneNumber"] = user.phoneNumber ?: [NSNull null];
        result[@"photoUrl"] = user.photoURL ? user.photoURL.absoluteString : [NSNull null];
        result[@"uid"] = user.uid;
        result[@"providerId"] = user.providerID;
        result[@"isAnonymous"] = @(user.isAnonymous);

        NSMutableArray* providers = [NSMutableArray array];
        for (id<FIRUserInfo> profile in user.providerData) {
            NSMutableDictionary* provider = [NSMutableDictionary dictionary];
            provider[@"providerId"] = profile.providerID ?: [NSNull null];
            provider[@"uid"] = profile.uid ?: [NSNull null];
            provider[@"displayName"] = profile.displayName ?: [NSNull null];
            provider[@"email"] = profile.email ?: [NSNull null];
            provider[@"phoneNumber"] = profile.phoneNumber ?: [NSNull null];
            provider[@"photoUrl"] = profile.photoURL ? profile.photoURL.absoluteString : [NSNull null];
            [providers addObject:provider];
        }
        result[@"providers"] = providers;

        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

#pragma mark - User Management

- (void)updateUserProfile:(CDVInvokedUrlCommand*)command {
    NSDictionary* profile = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            FIRUserProfileChangeRequest* changeRequest = [user profileChangeRequest];

            if (profile[@"displayName"]) {
                changeRequest.displayName = profile[@"displayName"];
            }
            if (profile[@"photoUri"]) {
                changeRequest.photoURL = [NSURL URLWithString:profile[@"photoUri"]];
            }

            [changeRequest commitChangesWithCompletion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)updateUserEmail:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user sendEmailVerificationBeforeUpdatingEmail:email completion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)sendUserEmailVerification:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;

            void (^completionBlock)(NSError* _Nullable) = ^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            };

            if (command.arguments.count > 0 && ![[command.arguments objectAtIndex:0] isEqual:[NSNull null]]) {
                NSDictionary* settingsDict = [command.arguments objectAtIndex:0];
                FIRActionCodeSettings* settings = [[FIRActionCodeSettings alloc] init];
                settings.URL = [NSURL URLWithString:settingsDict[@"url"]];
                if (settingsDict[@"handleCodeInApp"]) {
                    settings.handleCodeInApp = [settingsDict[@"handleCodeInApp"] boolValue];
                }
                if (settingsDict[@"iOS"]) {
                    settings.IOSBundleID = settingsDict[@"iOS"][@"bundleId"];
                }
                if (settingsDict[@"android"]) {
                    [settings setAndroidPackageName:settingsDict[@"android"][@"packageName"]
                                    installIfNotAvailable:[settingsDict[@"android"][@"installApp"] boolValue]
                                    minimumVersion:settingsDict[@"android"][@"minimumVersion"]];
                }
                if (settingsDict[@"dynamicLinkDomain"]) {
                    settings.dynamicLinkDomain = settingsDict[@"dynamicLinkDomain"];
                }
                [user sendEmailVerificationWithActionCodeSettings:settings completion:completionBlock];
            } else {
                [user sendEmailVerificationWithCompletion:completionBlock];
            }
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)verifyBeforeUpdateEmail:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;

            void (^completionBlock)(NSError* _Nullable) = ^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            };

            if (command.arguments.count > 1 && ![[command.arguments objectAtIndex:1] isEqual:[NSNull null]]) {
                NSDictionary* settingsDict = [command.arguments objectAtIndex:1];
                FIRActionCodeSettings* settings = [[FIRActionCodeSettings alloc] init];
                settings.URL = [NSURL URLWithString:settingsDict[@"url"]];
                if (settingsDict[@"handleCodeInApp"]) {
                    settings.handleCodeInApp = [settingsDict[@"handleCodeInApp"] boolValue];
                }
                if (settingsDict[@"dynamicLinkDomain"]) {
                    settings.dynamicLinkDomain = settingsDict[@"dynamicLinkDomain"];
                }
                [user sendEmailVerificationBeforeUpdatingEmail:email actionCodeSettings:settings completion:completionBlock];
            } else {
                [user sendEmailVerificationBeforeUpdatingEmail:email completion:completionBlock];
            }
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)updateUserPassword:(CDVInvokedUrlCommand*)command {
    NSString* password = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user updatePassword:password completion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)sendUserPasswordResetEmail:(CDVInvokedUrlCommand*)command {
    NSString* email = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] sendPasswordResetWithEmail:email completion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)deleteUser:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user deleteWithCompletion:^(NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Config

- (void)useAuthEmulator:(CDVInvokedUrlCommand*)command {
    NSString* host = [command.arguments objectAtIndex:0];
    NSNumber* port = [command.arguments objectAtIndex:1];
    [self.commandDelegate runInBackground:^{
        @try {
            [[FIRAuth auth] useEmulatorWithHost:host port:[port integerValue]];
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

- (void)getClaims:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            [user getIDTokenResultWithCompletion:^(FIRAuthTokenResult* _Nullable tokenResult, NSError* _Nullable error) {
                if (error) {
                    [self sendErrorResult:error command:command];
                } else {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:tokenResult.claims];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            }];
        } @catch (NSException *exception) {
            [self sendExceptionResult:exception command:command];
        }
    }];
}

#pragma mark - Auth Result Handling

- (void)handleAuthResult:(FIRAuthDataResult*)authResult error:(NSError*)error command:(CDVInvokedUrlCommand*)command {
    if (error) {
        NSDictionary* errorResult = [self createAuthErrorResult:error];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:errorResult];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        return;
    }

    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    FIRUser* user = authResult.user;
    if (user) {
        result[@"name"] = user.displayName ?: [NSNull null];
        result[@"email"] = user.email ?: [NSNull null];
        result[@"emailIsVerified"] = @(user.emailVerified);
        result[@"phoneNumber"] = user.phoneNumber ?: [NSNull null];
        result[@"photoUrl"] = user.photoURL ? user.photoURL.absoluteString : [NSNull null];
        result[@"uid"] = user.uid;
        result[@"providerId"] = user.providerID;
        result[@"isAnonymous"] = @(user.isAnonymous);
    }

    FIRAuthCredential* credential = authResult.credential;
    if (credential) {
        NSNumber* key = [self saveAuthCredential:credential];
        result[@"key"] = key;

        if ([credential isKindOfClass:[FIROAuthCredential class]]) {
            FIROAuthCredential* oauthCredential = (FIROAuthCredential*)credential;
            result[@"idToken"] = oauthCredential.idToken ?: [NSNull null];
            result[@"accessToken"] = oauthCredential.accessToken ?: [NSNull null];
            result[@"secret"] = oauthCredential.secret ?: [NSNull null];
        }
    }

    if (authResult.additionalUserInfo) {
        result[@"isNewUser"] = @(authResult.additionalUserInfo.isNewUser);
        if (authResult.additionalUserInfo.profile) {
            result[@"profile"] = authResult.additionalUserInfo.profile;
        }
    }

    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (NSDictionary*)createAuthErrorResult:(NSError*)error {
    NSMutableDictionary* errorResult = [NSMutableDictionary dictionary];
    errorResult[@"code"] = [NSString stringWithFormat:@"auth/%ld", (long)error.code];
    errorResult[@"message"] = error.localizedDescription ?: @"Unknown error";

    // Check for multi-factor auth required
    if (error.code == FIRAuthErrorCodeSecondFactorRequired) {
        errorResult[@"code"] = @"auth/multi-factor-auth-required";
        FIRMultiFactorResolver* resolver = error.userInfo[FIRAuthErrorUserInfoMultiFactorResolverKey];
        if (resolver) {
            self.multiFactorResolver = resolver;
            NSMutableArray* secondFactors = [NSMutableArray array];
            for (FIRMultiFactorInfo* info in resolver.hints) {
                NSMutableDictionary* factor = [NSMutableDictionary dictionary];
                factor[@"displayName"] = info.displayName ?: [NSNull null];
                factor[@"factorId"] = info.factorID;
                if ([info isKindOfClass:[FIRPhoneMultiFactorInfo class]]) {
                    FIRPhoneMultiFactorInfo* phoneInfo = (FIRPhoneMultiFactorInfo*)info;
                    factor[@"phoneNumber"] = phoneInfo.phoneNumber;
                }
                [secondFactors addObject:factor];
            }
            errorResult[@"secondFactors"] = secondFactors;
        }
    }

    // Check for credential-already-in-use
    if (error.code == FIRAuthErrorCodeCredentialAlreadyInUse) {
        FIRAuthCredential* updatedCredential = error.userInfo[FIRAuthErrorUserInfoUpdatedCredentialKey];
        if (updatedCredential) {
            NSNumber* key = [self saveAuthCredential:updatedCredential];
            errorResult[@"key"] = key;
        }
    }

    return errorResult;
}

#pragma mark - Auth Credential Management

- (NSNumber*)saveAuthCredential:(FIRAuthCredential*)credential {
    NSNumber* key = [self generateId];
    [self.authCredentials setObject:credential forKey:key];
    return key;
}

- (FIRAuthCredential*)obtainAuthCredential:(CDVInvokedUrlCommand*)command {
    @try {
        id arg = [command.arguments objectAtIndex:0];
        NSNumber* key;

        if ([arg isKindOfClass:[NSDictionary class]]) {
            key = [(NSDictionary*)arg objectForKey:@"key"];
        } else if ([arg isKindOfClass:[NSNumber class]]) {
            key = (NSNumber*)arg;
        } else if ([arg isKindOfClass:[NSString class]]) {
            key = @([(NSString*)arg integerValue]);
        }

        if (key && [self.authCredentials objectForKey:key]) {
            return [self.authCredentials objectForKey:key];
        }

        // Try to interpret as verificationId/code pair
        if (command.arguments.count >= 2) {
            NSString* verificationId = [arg isKindOfClass:[NSString class]] ? arg : [arg description];
            NSString* code = [[command.arguments objectAtIndex:1] description];
            return [[FIRPhoneAuthProvider provider] credentialWithVerificationID:verificationId verificationCode:code];
        }
    } @catch (NSException *exception) {
        NSLog(@"[FirebasexAuth] Error obtaining auth credential: %@", exception);
    }
    return nil;
}

- (BOOL)isSignedIn {
    return [FIRAuth auth].currentUser != nil;
}

- (BOOL)userNotSignedInError:(CDVInvokedUrlCommand*)command {
    if (![self isSignedIn]) {
        [self sendErrorMessage:@"No user is currently signed in" command:command];
        return YES;
    }
    return NO;
}

- (NSNumber*)generateId {
    NSNumber* key;
    do {
        key = @(arc4random_uniform(100000));
    } while ([self.authCredentials objectForKey:key]);
    return key;
}

#pragma mark - Utility Methods

- (void)sendErrorResult:(NSError*)error command:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:error.localizedDescription];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)sendErrorMessage:(NSString*)message command:(CDVInvokedUrlCommand*)command {
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:message];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)sendExceptionResult:(NSException*)exception command:(CDVInvokedUrlCommand*)command {
    NSLog(@"[FirebasexAuth] Exception: %@", exception);
    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

@end
