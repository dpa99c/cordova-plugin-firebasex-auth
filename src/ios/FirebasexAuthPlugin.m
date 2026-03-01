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
            NSMutableArray* result = [self parseEnrolledSecondFactorsToJson:enrolledFactors];
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
            NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
            [result setValue:@"true" forKey:@"instantVerification"];
            [result setValue:key forKey:@"id"];
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
                    [returnResult setValue:@"true" forKey:@"instantVerification"];
                    [returnResult setValue:key forKey:@"id"];
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
    @try {
        NSString* providerId = @"microsoft.com";
        NSMutableDictionary* customParameters = [[NSMutableDictionary alloc] init];
        [customParameters setValue:@"consent" forKey:@"prompt"];

        NSString* locale = [command.arguments objectAtIndex:0];
        if (locale != nil) {
            [customParameters setValue:locale forKey:@"locale"];
        }

        [self authenticateWithOAuth:providerId customParameters:customParameters scopes:nil command:command];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (void)authenticateUserWithFacebook:(CDVInvokedUrlCommand*)command {
    @try {
        NSString* accessToken = [command.arguments objectAtIndex:0];
        FIRAuthCredential* credential = [FIRFacebookAuthProvider credentialWithAccessToken:accessToken];
        NSNumber* key = [self saveAuthCredential:credential];
        NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
        [result setValue:@"true" forKey:@"instantVerification"];
        [result setValue:key forKey:@"id"];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (void)authenticateUserWithOAuth:(CDVInvokedUrlCommand*)command {
    @try {
        NSString* providerId = [command.arguments objectAtIndex:0];
        NSDictionary* customParameters = [command.arguments objectAtIndex:1];
        NSArray* scopes = [command.arguments objectAtIndex:2];

        [self authenticateWithOAuth:providerId customParameters:customParameters scopes:scopes command:command];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (void)authenticateWithOAuth:(NSString*)providerId customParameters:(NSDictionary*)customParameters scopes:(NSArray*)scopes command:(CDVInvokedUrlCommand*)command {
    @try {
        self.oauthProvider = [FIROAuthProvider providerWithProviderID:providerId];
        if (customParameters) {
            for (id key in customParameters) {
                id value = [customParameters objectForKey:key];
                [self.oauthProvider setCustomParameters:@{key : value}];
            }
        }
        if (scopes) {
            [self.oauthProvider setScopes:scopes];
        }

        [self.oauthProvider getCredentialWithUIDelegate:nil completion:^(FIRAuthCredential* _Nullable credential, NSError* _Nullable error) {
            CDVPluginResult* pluginResult;
            if (error) {
                pluginResult = [self createAuthErrorResult:error];
            } else if (credential) {
                NSNumber* key = [self saveAuthCredential:credential];
                NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
                [result setValue:@"true" forKey:@"instantVerification"];
                [result setValue:key forKey:@"id"];
                pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
            }
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
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
        result[@"instantVerification"] = @"true";
        result[@"id"] = key;
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
    NSMutableDictionary* result = [NSMutableDictionary dictionary];
    [result setValue:user.displayName forKey:@"name"];
    [result setValue:user.email forKey:@"email"];
    [result setValue:@(user.isEmailVerified ? true : false) forKey:@"emailIsVerified"];
    [result setValue:user.phoneNumber forKey:@"phoneNumber"];
    [result setValue:user.photoURL ? user.photoURL.absoluteString : nil forKey:@"photoUrl"];
    [result setValue:user.uid forKey:@"uid"];
    [result setValue:@(user.isAnonymous ? true : false) forKey:@"isAnonymous"];

    FIRUserMetadata* metadata = user.metadata;
    result[@"creationTimestamp"] = [self getTimestampFromDate:metadata.creationDate];
    result[@"lastSignInTimestamp"] = [self getTimestampFromDate:metadata.lastSignInDate];

    NSMutableArray* providers = [NSMutableArray array];
    for (id<FIRUserInfo> profile in user.providerData) {
        NSMutableDictionary* provider = [NSMutableDictionary dictionary];
        provider[@"providerId"] = profile.providerID;
        provider[@"uid"] = profile.uid;
        provider[@"displayName"] = profile.displayName;
        provider[@"email"] = profile.email;
        provider[@"phoneNumber"] = profile.phoneNumber;
        provider[@"photoUrl"] = [profile.photoURL absoluteString];
        [providers addObject:provider];
    }
    result[@"providers"] = providers;

    [user getIDTokenWithCompletion:^(NSString* _Nullable token, NSError* _Nullable error) {
        if (error == nil) {
            [result setValue:token forKey:@"idToken"];
        }
        [user getIDTokenResultWithCompletion:^(FIRAuthTokenResult* _Nullable tokenResult, NSError* _Nullable error) {
            if (error == nil) {
                [result setValue:tokenResult.signInProvider forKey:@"providerId"];
            }
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:result];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
        }];
    }];
}

- (NSNumber*)getTimestampFromDate:(NSDate*)date {
    if (date == nil) return nil;
    return @([date timeIntervalSince1970] * 1000);
}

#pragma mark - User Management

- (void)updateUserProfile:(CDVInvokedUrlCommand*)command {
    NSDictionary* profile = [command.arguments objectAtIndex:0];
    [self.commandDelegate runInBackground:^{
        @try {
            if ([self userNotSignedInError:command]) return;

            FIRUser* user = [FIRAuth auth].currentUser;
            FIRUserProfileChangeRequest* changeRequest = [user profileChangeRequest];

            if (profile[@"name"]) {
                changeRequest.displayName = profile[@"name"];
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

- (NSMutableArray*)parseEnrolledSecondFactorsToJson:(NSArray*)multiFactorInfos {
    NSMutableArray* secondFactors = [NSMutableArray new];
    int index = 0;
    for (FIRMultiFactorInfo* multiFactorInfo in multiFactorInfos) {
        NSMutableDictionary* secondFactor = [[NSMutableDictionary alloc] init];
        [secondFactor setValue:[NSNumber numberWithInt:index] forKey:@"index"];
        if (multiFactorInfo.displayName != nil) {
            [secondFactor setValue:multiFactorInfo.displayName forKey:@"displayName"];
        }

        FIRPhoneMultiFactorInfo* phoneMultiFactorInfo = (FIRPhoneMultiFactorInfo*)multiFactorInfo;
        if ([phoneMultiFactorInfo respondsToSelector:@selector(phoneNumber)]) {
            [secondFactor setValue:phoneMultiFactorInfo.phoneNumber forKey:@"phoneNumber"];
        }
        [secondFactors addObject:secondFactor];
        index++;
    }
    return secondFactors;
}

- (void)handleAuthResult:(FIRAuthDataResult*)authResult error:(NSError*)error command:(CDVInvokedUrlCommand*)command {
    @try {
        CDVPluginResult* pluginResult;
        if (error) {
            pluginResult = [self createAuthErrorResult:error];
        } else if (authResult == nil) {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"User not signed in"];
        } else {
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:true];
        }
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    } @catch (NSException *exception) {
        [self sendExceptionResult:exception command:command];
    }
}

- (CDVPluginResult*)createAuthErrorResult:(NSError*)error {
    CDVPluginResult* pluginResult;
    if (error.code == FIRAuthErrorCodeSecondFactorRequired) {
        self.multiFactorResolver = (FIRMultiFactorResolver*)error.userInfo[FIRAuthErrorUserInfoMultiFactorResolverKey];
        NSMutableArray* secondFactors = [self parseEnrolledSecondFactorsToJson:self.multiFactorResolver.hints];
        NSString* errMessage = @"Second factor required";

        NSMutableDictionary* result = [[NSMutableDictionary alloc] init];
        [result setValue:errMessage forKey:@"errorMessage"];
        [result setValue:secondFactors forKey:@"secondFactors"];

        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:result];
    } else if (error.code == FIRAuthErrorCodeCredentialAlreadyInUse) {
        NSMutableDictionary* userInfo = [NSMutableDictionary dictionaryWithDictionary:[error userInfo]];
        FIROAuthCredential* updatedCredential = userInfo[FIRAuthErrorUserInfoUpdatedCredentialKey];
        NSMutableDictionary* responseDict = [[NSMutableDictionary alloc] init];

        [responseDict setValue:@(error.code) forKey:@"errorCode"];
        [responseDict setValue:error.domain forKey:@"errorDomain"];
        [responseDict setValue:userInfo.description forKey:@"errorDescription"];
        if (userInfo[FIRAuthErrorUserInfoNameKey]) {
            [responseDict setValue:userInfo[FIRAuthErrorUserInfoNameKey] forKey:FIRAuthErrorUserInfoNameKey];
        }
        if (userInfo[FIRAuthErrorUserInfoEmailKey]) {
            [responseDict setValue:userInfo[FIRAuthErrorUserInfoEmailKey] forKey:FIRAuthErrorUserInfoEmailKey];
        }
        if (userInfo[FIRAuthErrorUserInfoNameKey]) {
            [responseDict setValue:userInfo[FIRAuthErrorUserInfoNameKey] forKey:FIRAuthErrorUserInfoNameKey];
        }

        if (updatedCredential) {
            NSMutableDictionary* updatedCredentialDict = [[NSMutableDictionary alloc] init];
            if (updatedCredential.provider) {
                [updatedCredentialDict setValue:updatedCredential.provider forKey:@"provider"];
            }
            if (updatedCredential.IDToken) {
                [updatedCredentialDict setValue:updatedCredential.IDToken forKey:@"IDToken"];
            }
            NSNumber* key = [self saveAuthCredential:updatedCredential];
            [updatedCredentialDict setValue:key forKey:@"id"];
            [responseDict setValue:updatedCredentialDict forKey:@"updatedCredential"];
        }

        NSString* jsonString = [[NSString alloc] initWithData:[NSJSONSerialization dataWithJSONObject:responseDict options:0 error:nil] encoding:NSUTF8StringEncoding];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:jsonString];
    } else {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:error.description];
    }
    return pluginResult;
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

        if (arg == nil || [arg isEqual:[NSNull null]]) {
            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"credential object must be passed as first and only argument"];
            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
            return nil;
        }

        if ([arg isKindOfClass:[NSDictionary class]]) {
            NSDictionary* credential = (NSDictionary*)arg;
            NSString* keyStr = [credential objectForKey:@"id"];
            NSString* verificationId = [credential objectForKey:@"verificationId"];
            NSString* code = [credential objectForKey:@"code"];

            if (keyStr != nil) {
                NSNumber* key = @([keyStr integerValue]);
                FIRAuthCredential* authCredential = [self.authCredentials objectForKey:key];
                if (authCredential == nil) {
                    NSString* errMsg = [NSString stringWithFormat:@"no native auth credential exists for specified id '%@'", keyStr];
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errMsg];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
                return authCredential;
            } else if (verificationId != nil && code != nil) {
                return [[FIRPhoneAuthProvider provider] credentialWithVerificationID:verificationId verificationCode:code];
            } else {
                CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:@"credential object must either specify the id key of an existing native auth credential or the verificationId/code keys must be specified for a phone number authentication"];
                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                return nil;
            }
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
