# cordova-plugin-firebasex-auth

[![npm version](https://img.shields.io/npm/v/cordova-plugin-firebasex-auth.svg)](https://www.npmjs.com/package/cordova-plugin-firebasex-auth)

Firebase Authentication module for the [modular FirebaseX Cordova plugin suite](https://github.com/dpa99c/cordova-plugin-firebasex#modular-plugins).

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Installation](#installation)
  - [Plugin variables](#plugin-variables)
- [API](#api)
  - [isUserSignedIn](#isusersignedin)
  - [signOutUser](#signoutuser)
  - [getCurrentUser](#getcurrentuser)
  - [reloadCurrentUser](#reloadcurrentuser)
  - [updateUserProfile](#updateuserprofile)
  - [updateUserEmail](#updateuseremail)
  - [sendUserEmailVerification](#senduseremailverification)
  - [verifyBeforeUpdateEmail](#verifybeforeupdateemail)
  - [updateUserPassword](#updateuserpassword)
  - [sendUserPasswordResetEmail](#senduserpasswordresetemail)
  - [deleteUser](#deleteuser)
  - [createUserWithEmailAndPassword](#createuserwithemailandpassword)
  - [signInUserWithEmailAndPassword](#signinuserwithemailandpassword)
  - [signInUserWithCustomToken](#signinuserwithcustomtoken)
  - [signInUserAnonymously](#signinuseranonymously)
  - [verifyPhoneNumber](#verifyphonenumber)
    - [Android](#android)
    - [iOS](#ios)
  - [enrollSecondAuthFactor](#enrollsecondauthfactor)
  - [verifySecondAuthFactor](#verifysecondauthfactor)
  - [listEnrolledSecondAuthFactors](#listenrolledsecondauthfactors)
  - [unenrollSecondAuthFactor](#unenrollsecondauthfactor)
  - [setLanguageCode](#setlanguagecode)
  - [authenticateUserWithEmailAndPassword](#authenticateuserwithemailandpassword)
  - [authenticateUserWithGoogle](#authenticateuserwithgoogle)
    - [Android](#android-1)
    - [iOS](#ios-1)
  - [authenticateUserWithApple](#authenticateuserwithapple)
    - [iOS](#ios-2)
    - [Android](#android-2)
  - [authenticateUserWithMicrosoft](#authenticateuserwithmicrosoft)
  - [authenticateUserWithFacebook](#authenticateuserwithfacebook)
  - [authenticateUserWithOAuth](#authenticateuserwithoauth)
  - [signInWithCredential](#signinwithcredential)
  - [linkUserWithCredential](#linkuserwithcredential)
  - [reauthenticateWithCredential](#reauthenticatewithcredential)
  - [unlinkUserWithProvider](#unlinkuserwithprovider)
  - [registerAuthStateChangeListener](#registerauthstatechangelistener)
  - [registerAuthIdTokenChangeListener](#registerauthidtokenchangelistener)
  - [useAuthEmulator](#useauthemulator)
  - [getClaims](#getclaims)
- [Reporting issues](#reporting-issues)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# Installation

Install the plugin by adding it to your project's config.xml:

    cordova plugin add cordova-plugin-firebasex-auth

or by running:

    cordova plugin add cordova-plugin-firebasex-auth

**This module depends on `cordova-plugin-firebasex-core` which will be installed automatically as a dependency.**

## Plugin variables

The following plugin variables are used to configure the auth module at install time.
They can be set on the command line at plugin installation time:

    cordova plugin add cordova-plugin-firebasex-auth --variable VARIABLE_NAME=value

Or in your `config.xml`:

    <plugin name="cordova-plugin-firebasex-auth">
        <variable name="VARIABLE_NAME" value="value" />
    </plugin>

| Variable | Default | Description |
|---|---|---|
| `ANDROID_FIREBASE_AUTH_VERSION` | `24.0.1` | Android Firebase Auth SDK version. |
| `ANDROID_PLAY_SERVICES_AUTH_VERSION` | `21.3.0` | Android Play Services Auth version. |
| `ANDROID_CREDENTIALS_VERSION` | `1.3.0` | AndroidX Credentials library version. |
| `ANDROID_GOOGLEID_VERSION` | `1.1.1` | Google Identity library version. |
| `IOS_FIREBASE_SDK_VERSION` | `12.9.0` | iOS Firebase SDK version (for auth pod). |
| `SETUP_RECAPTCHA_VERIFICATION` | `false` | Set to `true` to automatically add the `REVERSED_CLIENT_ID` from `GoogleService-Info.plist` to the list of custom URL schemes for reCAPTCHA verification on iOS. See [verifyPhoneNumber - iOS](#ios) for more info. |
| `IOS_ENABLE_APPLE_SIGNIN` | `false` | Set to `true` to add the Apple Sign-In entitlement to your iOS app. See [authenticateUserWithApple](#authenticateuserwithapple) for more info. |
| `IOS_GOOGLE_SIGIN_VERSION` | `9.0.0` | Google Sign-In iOS SDK version |

# API

The following methods are available via the `FirebasexAuth` global object.

## isUserSignedIn

Checks if there is a current Firebase user signed into the app.

**Parameters**:

-   {function} success - callback function to pass {boolean} result to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.isUserSignedIn(
    function (isSignedIn) {
        console.log("User " + (isSignedIn ? "is" : "is not") + " signed in");
    },
    function (error) {
        console.error("Failed to check if user is signed in: " + error);
    }
);
```

## signOutUser

Signs current Firebase user out of the app.

**Parameters**:

-   {function} success - callback function to pass {boolean} result to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.signOutUser(
    function () {
        console.log("User signed out");
    },
    function (error) {
        console.error("Failed to sign out user: " + error);
    }
);
```

## getCurrentUser

Returns details of the currently logged in user from local Firebase SDK.
Note that some user properties will be empty is they are not defined in Firebase for the current user.

**Parameters**:

-   {function} success - callback function to pass user {object} to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.getCurrentUser(
    function (user) {
        console.log("Name: " + user.name);
        console.log("Email: " + user.email);
        console.log("Is email verified?: " + user.emailIsVerified);
        console.log("Phone number: " + user.phoneNumber);
        console.log("Photo URL: " + user.photoUrl);
        console.log("UID: " + user.uid);
        console.log("Provider ID: " + user.providerId);
        console.log("ID token: " + user.idToken);
        console.log("creationTime", user.creationTimestamp);
        console.log("lastSignInTime", user.lastSignInTimestamp);

        for (var i = 0; i < user.providers.length; i++) {
            console.log("providerId", user.providers[i].providerId);
            console.log("uid", user.providers[i].uid);
            console.log("displayName", user.providers[i].displayName);
            console.log("email", user.providers[i].email);
            console.log("phoneNumber", user.providers[i].phoneNumber);
            console.log("photoUrl", user.providers[i].photoUrl);
        }
    },
    function (error) {
        console.error("Failed to get current user data: " + error);
    }
);
```

## reloadCurrentUser

Loads details of the currently logged in user from remote Firebase server.
This differs from `getCurrentUser()` which loads the locally cached details which may be stale.
For example, if you want to check if a user has verified their email address, this method will guarantee the reported verified state is up-to-date.

**Parameters**:

-   {function} success - callback function to pass user {object} to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.reloadCurrentUser(
    function (user) {
        console.log("Name: " + user.name);
        console.log("Email: " + user.email);
        console.log("Is email verified?: " + user.emailIsVerified);
        console.log("Phone number: " + user.phoneNumber);
        console.log("Photo URL: " + user.photoUrl);
        console.log("UID: " + user.uid);
        console.log("Provider ID: " + user.providerId);
        console.log("ID token: " + user.idToken);
    },
    function (error) {
        console.error("Failed to reload current user data: " + error);
    }
);
```

## updateUserProfile

Updates the display name and/or photo URL of the current Firebase user signed into the app.

**Parameters**:

-   {object} profile - new profile details:
    -   {string} name - display name of user
    -   {string} photoUri - URL of user profile photo
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.updateUserProfile(
    {
        name: "Homer Simpson",
        photoUri: "http://homer.simpson.com/photo.png",
    },
    function () {
        console.log("User profile successfully updated");
    },
    function (error) {
        console.error("Failed to update user profile: " + error);
    }
);
```

## updateUserEmail

Updates/sets the email address of the current Firebase user signed in to the app.

**Parameters**:

-   {string} email - email address of user to set as current
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.updateUserEmail(
    "user@somewhere.com",
    function () {
        console.log("User email successfully updated");
    },
    function (error) {
        console.error("Failed to update user email: " + error);
    }
);
```

## sendUserEmailVerification

Sends a verification email to the currently configured email address of the current Firebase user signed into the app.
When the user opens the contained link, their email address will have been verified.

**Parameters**:

-   {object} actionCodeSettings - action code settings based on [Passing State in Email Actions Parameters](https://firebase.google.com/docs/auth/web/passing-state-in-email-actions#passing_statecontinue_url_in_email_actions) :
    -   {boolean} handleCodeInApp - Whether the email action link will be opened in a mobile app or a web link first
    -   {string} url - Continue URL after email has been verified
    -   {string} dynamicLinkDomain - Sets the dynamic link domain to use for the current link if it is to be opened using Firebase Dynamic Links
    -   {string} iosBundleId - Sets the iOS bundle ID. This will try to open the link in an iOS app if it is installed
    -   {string} androidPackageName - Sets the Android package name. This will try to open the link in an android app if it is installed
    -   {boolean} installIfNotAvailable - Install if the provided app package name is not already installed on the users device (Android only)
    -   {string} minimumVersion - minimum app version required (Android Only)
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.sendUserEmailVerification(
    {
        handleCodeInApp: true,
        url: "http://www.example.com",
        dynamicLinkDomain: "example.page.link",
        iosBundleId: "com.example.ios",
        androidPackageName: "com.example.android",
        installIfNotAvailable: true,
        minimumVersion: "12",
    },
    function () {
        console.log("User verification email successfully sent");
    },
    function (error) {
        console.error("Failed to send user verification email: " + error);
    }
);
```

## verifyBeforeUpdateEmail

First verifies the user's identity, then sets/updates the email address of the current Firebase user signed in to the app.

-   This is required when a user with multi-factor authentication enabled on their account wishes to change their registered email address.
    -   [updateUserEmail](#updateuseremail) cannot be used and will result in an error.
-   See [the Firebase documentation](https://cloud.google.com/identity-platform/docs/work-with-mfa-users#updating_a_users_email) regarding updating the email address of a user with multi-factor authentication enabled.

**Parameters**:

-   {string} email - email address of user to set as current
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.verifyBeforeUpdateEmail(
    "user@somewhere.com",
    function () {
        console.log("User verified and email successfully updated");
    },
    function (error) {
        console.error("Failed to verify user/update user email: " + error);
    }
);
```

## updateUserPassword

Updates/sets the account password for the current Firebase user signed into the app.

**Parameters**:

-   {string} password - user-defined password
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.updateUserPassword(
    "mypassword",
    function () {
        console.log("User password successfully updated");
    },
    function (error) {
        console.error("Failed to update user password: " + error);
    }
);
```

## sendUserPasswordResetEmail

Sends a password reset email to the specified user email address.
Note: doesn't require the Firebase user to be signed in to the app.

**Parameters**:

-   {string} email - email address of user
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.sendUserPasswordResetEmail(
    "user@somewhere.com",
    function () {
        console.log("User password reset email sent successfully");
    },
    function (error) {
        console.error("Failed to send user password reset email: " + error);
    }
);
```

## deleteUser

Deletes the account of the current Firebase user signed into the app.

**Parameters**:

-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

```javascript
FirebasexAuth.deleteUser(
    function () {
        console.log("User account deleted");
    },
    function (error) {
        console.error("Failed to delete current user account: " + error);
    }
);
```

## createUserWithEmailAndPassword

Creates a new email/password-based user account.
If account creation is successful, user will be automatically signed in.

**Parameters**:

-   {string} email - user email address. It is the responsibility of the app to ensure this is a valid email address.
-   {string} password - user password. It is the responsibility of the app to ensure the password is suitable.
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument.
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
FirebasexAuth.createUserWithEmailAndPassword(
    email,
    password,
    function () {
        console.log("Successfully created email/password-based user account");
        // User is now signed in
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            handleSecondFactorAuthentation(secondFactors); // you need to implement this
        } else {
            console.error(
                "Failed to create email/password-based user account",
                error
            );
        }
    }
);
```

## signInUserWithEmailAndPassword

Signs in to an email/password-based user account.

**Parameters**:

-   {string} email - user email address
-   {string} password - user password
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
FirebasexAuth.signInUserWithEmailAndPassword(
    email,
    password,
    function () {
        console.log("Successfully signed in");
        // User is now signed in
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            handleSecondFactorAuthentation(secondFactors); // you need to implement this
        } else {
            console.error("Failed to sign in", error);
        }
    }
);
```

## signInUserWithCustomToken

Signs in user with custom token.

**Parameters**:

-   {string} customToken - the custom token
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
FirebasexAuth.signInUserWithCustomToken(
    customToken,
    function () {
        console.log("Successfully signed in");
        // User is now signed in
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            handleSecondFactorAuthentation(secondFactors); // you need to implement this
        } else {
            console.error("Failed to sign in", error);
        }
    }
);
```

## signInUserAnonymously

Signs in user anonymously.

**Parameters**:

-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
FirebasexAuth.signInUserAnonymously(
    function () {
        console.log("Successfully signed in");
        // User is now signed in
    },
    function (error) {
        console.error("Failed to sign in", error);
    }
);
```

## verifyPhoneNumber

Requests verification of a phone number.
The resulting credential can be used to create/sign in to a phone number-based user account in your app or to link the phone number to an existing user account.

**NOTE: This will only work on physical devices with a SIM card (not iOS Simulator or Android Emulator)**

In response to your request, you'll receive a verification ID which you can use in conjunction with the verification code to sign the user in.

There are 3 verification scenarios:

-   Some Android devices support "instant verification" where the phone number can be instantly verified without sending or receiving an SMS.
    -   In this case, the user doesn't need to do anything in order for you to sign them in and you don't need to provide any additional credentials in order to sign the user in or link the user account to an existing Firebase user account.
-   Some Android devices support "auto-retrieval" where Google Play services is able to detect the incoming verification SMS and perform verification with no user action required.
    -   As above, the user doesn't need to do anything in order for you to sign them in.
-   For other Android devices and all iOS devices, the user must manually enter the verification code received in the SMS into your app.
    -   This code be used, along with the accompanying verification ID, to sign the user in or link phone number to an existing Firebase user account.

**Parameters**:

-   {function} success - callback function to pass {object} credentials to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {string} phoneNumber - phone number to verify
-   {object} opts - (optional) parameters
    -   {integer} timeOutDuration - (Android only) time to wait in seconds before timing out. Defaults to 30 seconds if not specified.
    -   {boolean} requireSmsValidation - (Android only) whether to always require SMS validation on Android even if instant verification is available. Defaults to false if not specified.
    -   {string} fakeVerificationCode - (Android only) to test instant verification on Android, specify a fake verification code to return for whitelisted phone numbers.
        -   See [Firebase SDK Phone Auth Android Integration Testing](https://firebase.google.com/docs/auth/android/phone-auth#integration-testing) for more info.

The success callback will be passed a credential object with the following possible properties:

-   {boolean} instantVerification - `true` if the Android device used instant verification to instantly verify the user without sending an SMS
    or used auto-retrieval to automatically read an incoming SMS.
    If this is `false`, the device will be sent an SMS containing the verification code.
    If the Android device supports auto-retrieval, on the device receiving the SMS, this success callback will be immediately invoked again with `instantVerification: true` and no user action will be required for verification since Google Play services will extract and submit the verification code.
    Otherwise the user must manually enter the verification code from the SMS into your app.
    Always `false` on iOS.
-   {string} id - the identifier of a native credential object which can be used for signing in the user.
    Will only be present if `instantVerification` is `true`.
-   {string} verificationId - the verification ID to be passed along with the verification code sent via SMS to sign the user in.
    Will only be present if `instantVerification` is `false`.

Example usage:

```javascript
var number = "+441234567890";
var timeOutDuration = 60;
var fakeVerificationCode = "123456";
var awaitingSms = false;

FirebasexAuth.verifyPhoneNumber(
    function (credential) {
        if (credential.instantVerification) {
            if (awaitingSms) {
                awaitingSms = false;
                // the Android device used auto-retrieval to extract and submit the verification code in the SMS so dismiss user input UI
                dismissUserPromptToInputCode();
            }
            signInWithCredential(credential);
        } else {
            awaitingSms = true;
            promptUserToInputCode() // you need to implement this
                .then(function (userEnteredCode) {
                    awaitingSms = false;
                    credential.code = userEnteredCode; // set the user-entered verification code on the credential object
                    signInWithCredential(credential);
                });
        }
    },
    function (error) {
        console.error(
            "Failed to verify phone number: " + JSON.stringify(error)
        );
    },
    number,
    {
        timeOutDuration: timeOutDuration,
        requireSmsValidation: false,
        fakeVerificationCode: fakeVerificationCode,
    }
);

function signInWithCredential(credential) {
    FirebasexAuth.signInWithCredential(
        credential,
        function () {
            console.log("Successfully signed in");
        },
        function (error) {
            console.error("Failed to sign in", error);
        }
    );
}
```

### Android

To use phone auth with your Android app, you need to configure your app SHA-1 hash in the android app configuration in the Firebase console.
See [this guide](https://developers.google.com/android/guides/client-auth) to find how to your SHA-1 app hash.
See the [Firebase phone auth integration guide for native Android](https://firebase.google.com/docs/auth/android/phone-auth) for more information.

### iOS

When you call this method on iOS, FCM sends a silent push notification to the iOS device to verify it.
So to use phone auth with your iOS app, you need to:

-   [setup your iOS app for push notifications](https://firebase.google.com/docs/cloud-messaging/ios/certs)
-   Verify that push notifications are arriving on your physical device
-   [Upload your APNs auth key to the Firebase console](https://firebase.google.com/docs/cloud-messaging/ios/client#upload_your_apns_authentication_key).

You can [set up reCAPTCHA verification for iOS](https://firebase.google.com/docs/auth/ios/phone-auth#set-up-recaptcha-verification) automatically by specifying the `SETUP_RECAPTCHA_VERIFICATION` plugin variable at plugin install time:

    cordova plugin add cordova-plugin-firebasex-auth --variable SETUP_RECAPTCHA_VERIFICATION=true

This adds the `REVERSED_CLIENT_ID` from the `GoogleService-Info.plist` to the list of custom URL schemes in your Xcode project, so you don't need to do this manually.

## enrollSecondAuthFactor

Enrolls a user-specified phone number as a second factor for multi-factor authentication (MFA).

-   As with [verifyPhoneNumber](#verifyphonenumber), this may require the user to manually input the verification code received in an SMS message.
    -   In this case, once the user has entered the code, `enrollSecondAuthFactor` will need to be called again with the `credential` option used to specified the `code` and verification `id`.
-   This function involves a similar verification flow to [verifyPhoneNumber](#verifyphonenumber) and therefore has the same pre-requisites and requirements.
-   See the Firebase MFA documentation for [Android](https://cloud.google.com/identity-platform/docs/android/mfa) and [iOS](https://cloud.google.com/identity-platform/docs/ios/mfa) for more information on MFA-specific setup requirements.
-   Calling when no user is signed in will result in error callback being invoked.

**Parameters**:

-   {function} success - callback function to invoke either upon:
    -   successful enrollment: will be passed `true` as an argument
    -   user-entered verification code required: will be passed a `credential` object with a verification `id`.
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {string} phoneNumber - phone number to enroll
-   {object} opts - (optional) parameters
    -   {string} displayName - display name for second factor.
        -   Used when a user has multiple second factor phone numbers enrolled and asking them which to use since the full phone number is masked.
        -   If not specified, defaults to the masked phone number.
    -   {object} credential - if manual entry of the verification code in an SMS is required, the `credential` object will be passed to the `success` function. The user-entered code should be appended to this object as the `code` property then this function re-invoked with the `credential` specified in the `opts` argument.
    -   {integer} timeOutDuration - (Android only) time to wait in seconds before timing out. Defaults to 30 seconds if not specified.
    -   {boolean} requireSmsValidation - (Android only) whether to always require SMS validation on Android even if instant verification is available. Defaults to false if not specified.
    -   {string} fakeVerificationCode - (Android only) to test instant verification on Android, specify a fake verification code to return for whitelisted phone numbers.
        -   See [Firebase SDK Phone Auth Android Integration Testing](https://firebase.google.com/docs/auth/android/phone-auth#integration-testing) for more info.

Example usage:

```javascript
var phoneNumber = "+441234567890";
var timeOutDuration = 60;
var fakeVerificationCode = "123456";
var displayName = "Work phone";
var credential;

function enrollSecondAuthFactor() {
    FirebasexAuth.enrollSecondAuthFactor(
        function (result) {
            if (typeof result === "object") {
                // User must enter SMS verification code manually
                credential = result;
                promptUserToInputCode() // you need to implement this
                    .then(function (userEnteredCode) {
                        credential.code = userEnteredCode; // set the user-entered verification code on the credential object
                        enrollSecondAuthFactor(); // re-invoke the function with the credential
                    });
            } else {
                console.log("Second factor successfully enrolled");
            }
        },
        function (error) {
            console.error(
                "Failed to enroll second factor: " + JSON.stringify(error)
            );
        },
        phoneNumber,
        {
            displayName: displayName,
            credential: credential,
            timeOutDuration: timeOutDuration,
            requireSmsValidation: false,
            fakeVerificationCode: fakeVerificationCode,
        }
    );
}
enrollSecondAuthFactor();
```

## verifySecondAuthFactor

Verifies a second factor phone number for multi-factor authentication (MFA).

-   If a user has MFA enrolled on their account, when they try to perform an authentication operation, such as sign-in using one of the first factor methods (e.g. [signInUserWithEmailAndPassword](#signinuserwithemailandpassword)), the error callback of that function will be invoked.
    -   The first argument passed to the error callback will be the error message: "Second factor required"
    -   A second argument will be passed containing the list of (one or more) enrolled second factors for that user; each factor in the list will be an object with the following properties:
        -   {integer} index - index of the factor in the list - specify this as `selectedIndex` to select this factor.
        -   {string} displayName - name of factor specified by the user when this factor was enrolled.
            -   If no name was specified during enrollment, defaults to the masked phone number.
        -   {string} phoneNumber - phone number for this factor.
-   The app should then call this function, specifying the `selectedIndex` of the second factor in the `params` argument.
    -   If there is more than one second factor enrolled, the app should ask the user to select which one to use and specify the index of this as the `selectedIndex`
    -   If there is only one, the `selectedIndex` should be specified as `0`.
-   As with [verifyPhoneNumber](#verifyphonenumber), this may require the user to manually input the verification code received in an SMS message.
    -   In this case, once the user has entered the code, `enrollSecondAuthFactor` will need to be called again with the `credential` option used to specified the `code` and verification `id`.
-   This function involves a similar verification flow to [verifyPhoneNumber](#verifyphonenumber) and therefore has the same pre-requisites and requirements.
-   See the Firebase MFA documentation for [Android](https://cloud.google.com/identity-platform/docs/android/mfa) and [iOS](https://cloud.google.com/identity-platform/docs/ios/mfa) for more information on MFA-specific setup requirements.

**Parameters**:

-   {function} success - callback function to invoke either upon:
    -   successful verification : will be passed `true` as an argument
    -   user-entered verification code required: will be passed a `credential` object with a verification `id`.
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {object} params - conditionally required parameters - either:
    -   {integer} selectedIndex - index of selected second factor phone number to use for verification.
    -   {object} credential - if manual entry of the verification code in an SMS is required, the `credential` object will be passed to the `success` function. The user-entered code should be appended to this object as the `code` property then this function re-invoked with the `credential` specified in the `opts` argument.
-   {object} opts - (optional Android only) parameters
    -   {integer} timeOutDuration - time to wait in seconds before timing out. Defaults to 30 seconds if not specified.
    -   {boolean} requireSmsValidation - whether to always require SMS validation on Android even if instant verification is available. Defaults to false if not specified.
    -   {string} fakeVerificationCode - to test instant verification on Android, specify a fake verification code to return for whitelisted phone numbers.
        -   See [Firebase SDK Phone Auth Android Integration Testing](https://firebase.google.com/docs/auth/android/phone-auth#integration-testing) for more info.
    -   {string} phoneNumber - phone number to use for fake instant verification - required if `fakeVerificationCode` is specified

Example usage:

```javascript
var selectedIndex, credential;

function verifySecondAuthFactor() {
    FirebasexAuth.verifySecondAuthFactor(
        function (result) {
            if (typeof result === "object") {
                // User must enter SMS verification code manually
                credential = result;
                promptUserToInputCode() // you need to implement this
                    .then(function (userEnteredCode) {
                        credential.code = userEnteredCode; // set the user-entered verification code on the credential object
                        verifySecondAuthFactor(); // re-invoke the function with the credential
                    });
            } else {
                console.log("Second factor successfully enrolled");
            }
        },
        function (error) {
            console.error(
                "Failed to enroll second factor: " + JSON.stringify(error)
            );
        },
        {
            selectedIndex: selectedIndex,
            credential: credential,
        }
    );
}

FirebasexAuth.signInWithCredential(
    credential,
    function () {
        console.log("Successfully signed in");
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            if (secondFactors.length === 1) {
                // Only 1 enrolled second factor so select and use it
                selectedIndex = 0;
                verifySecondAuthFactor();
            } else {
                // Multiple second factors enrolled so ask user to choose which to use
                promptUserToSelectFactor(secondFactors) // you need to implement this
                    .then(function (_selectedIndex) {
                        selectedIndex = _selectedIndex;
                        verifySecondAuthFactor();
                    });
            }
        } else {
            console.error("Failed to sign in", error);
        }
    }
);
```

## listEnrolledSecondAuthFactors

Lists the second factors the current user has enrolled for multi-factor authentication (MFA).

-   Calling when no user is signed in will result in error callback being invoked.

**Parameters**:

-   {function} success - callback function to invoke upon successfully retrieving second factors. Will be passed an {array} of second factor {object} with properties:

    -   {integer} index - index of the factor in the list
    -   {string} displayName - name of factor specified by the user when this factor was enrolled.
        -   If no name was specified during enrollment, defaults to the masked phone number.
    -   {string} phoneNumber - (Android only) enrolled phone number for this factor.
        -   On iOS, this is not available when listing enrolled factors.

-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
FirebasexAuth.listEnrolledSecondAuthFactors(
    function (secondFactors) {
        if (secondFactors.length > 0) {
            for (var secondFactor of secondFactors) {
                console.log(
                    `${secondFactor.index}: ${secondFactor.displayName}${
                        secondFactor.phoneNumber
                            ? " (" + secondFactor.phoneNumber + ")"
                            : ""
                    }`
                );
            }
        } else {
            console.log("No second factors are enrolled");
        }
    },
    function (error) {
        console.error(
            "Failed to list second factors: " + JSON.stringify(error)
        );
    }
);
```

## unenrollSecondAuthFactor

Unenrolls (removes) an enrolled second factor that the current user has enrolled for multi-factor authentication (MFA).

-   Calling when no user is signed in will result in error callback being invoked.

**Parameters**:

-   {function} success - callback function to invoke upon success
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {number} selectedIndex - Index of the second factor to unenroll (obtained using [listEnrolledSecondAuthFactors](#listenrolledsecondauthfactors))

Example usage:

```javascript
function unenrollSecondAuthFactor() {
    FirebasexAuth.listEnrolledSecondAuthFactors(
        function (secondFactors) {
            askUserToSelectSecondFactorToUnenroll(secondFactors) // you implement this
                .then(function (selectedIndex) {
                    FirebasexAuth.unenrollSecondAuthFactor(
                        function () {
                            console.log(
                                "Successfully unenrolled selected second factor"
                            );
                        },
                        function (error) {
                            console.error(
                                "Failed to unenroll second factor: " +
                                    JSON.stringify(error)
                            );
                        },
                        selectedIndex
                    );
                });
        },
        function (error) {
            console.error(
                "Failed to list second factors: " + JSON.stringify(error)
            );
        }
    );
}
```

## setLanguageCode

Sets the user-facing language code for auth operations that can be internationalized, such as sendEmailVerification() or verifyPhoneNumber(). This language code should follow the conventions defined by the IETF in BCP47.

**Parameters**:

-   {string} lang - language to change, ex: 'fr' for french

Example usage:

```javascript
FirebasexAuth.setLanguageCode("fr"); // will switch to french
```

## authenticateUserWithEmailAndPassword

Authenticates the user with email/password-based user account to obtain a credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

**Parameters**:

-   {string} email - user email address
-   {string} password - user password
-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
-   {function} error - callback function which will be passed a {string} error message as an argument
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
FirebasexAuth.authenticateUserWithEmailAndPassword(
    email,
    password,
    function (credential) {
        console.log("Successfully authenticated with email/password");
        FirebasexAuth.reauthenticateWithCredential(
            credential,
            function () {
                console.log("Successfully re-authenticated");
            },
            function (error) {
                console.error("Failed to re-authenticate", error);
            }
        );
        // User is now signed in
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            handleSecondFactorAuthentation(secondFactors); // you need to implement this
        } else {
            console.error("Failed to authenticate with email/password", error);
        }
    }
);
```

## authenticateUserWithGoogle

Authenticates the user with a Google account to obtain a credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

**Parameters**:

-   {string} clientId - your OAuth 2.0 client ID - [see here](https://developers.google.com/identity/sign-in/android/start-integrating#get_your_backend_servers_oauth_20_client_id) how to obtain it.
-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
    -   {string} idToken - the identity token from Google account. Could be useful if you want to sign-in with on JS layer.
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {object} options - (optional) Map of options.
    -   {boolean} useCredentialManager - (Android only) If true, use Android Credential Manager API. Defaults to false.

Example usage:

```javascript
FirebasexAuth.authenticateUserWithGoogle(
    clientId,
    function (credential) {
        FirebasexAuth.signInWithCredential(
            credential,
            function () {
                console.log("Successfully signed in");
            },
            function (error) {
                console.error("Failed to sign in", error);
            }
        );
    },
    function (error) {
        console.error("Failed to authenticate with Google: " + error);
    },
    {
        useCredentialManager: true
    }
);
```

### Android

To use Google Sign-in in your Android app you need to do the following:

-   Add the SHA-1 fingerprint of your app's signing key to your Firebase project
-   Enable Google Sign-in in the Firebase console

For details how to do the above, see the [Google Sign-In on Android page](https://firebase.google.com/docs/auth/android/google-signin) in the Firebase documentation.

### iOS

To use Google Sign-In on iOS:

-   Ensure `GoogleService-Info.plist` is present in your project root.
-   The plugin automatically configures the `REVERSED_CLIENT_ID` URL scheme.

**SceneDelegate Support (iOS 13+)**:

If your app uses `SceneDelegate`, you must handle the URL callback and forward it to `GIDSignIn`.

```swift
import GoogleSignIn

func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) {
    guard let url = URLContexts.first?.url else { return }
    GIDSignIn.sharedInstance.handle(url)
}
```

<br>

**Server side verification**

Once the id token has been obtained from `authenticateUserWithGoogle()` it can be sent to your server to get access to more information about the user's google account. However, it's recommended by Google that the id token be validated on your server before being used. You should generally not trust tokens supplied by clients without performing this validation. While you can write the code to perform this check yourself, it's strongly recommended that you use a library supplied by Google such as [google-auth-library](https://www.npmjs.com/package/google-auth-library) for this purpose.

The following is sample code taken from [Google documentation](https://developers.google.com/identity/sign-in/web/backend-auth) for performing a server side verification of an id token:

```javascript
const { OAuth2Client } = require("google-auth-library");

const client = new OAuth2Client(CLIENT_ID);

async function verify() {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: CLIENT_ID, // Specify the CLIENT_ID of the app that accesses the backend
        // Or, if multiple clients access the backend:
        //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
    });
    const payload = ticket.getPayload();
    const userid = payload["sub"];
    // If request specified a G Suite domain:
    // const domain = payload['hd'];
}
verify().catch(console.error);
```

<br>

## authenticateUserWithApple

Authenticates the user with an Apple account using Sign In with Apple to obtain a credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

To use Sign In with Apple you must ensure your app's provisioning profile has this capability and it is enabled in your Xcode project.
You can enable the capability in Xcode by setting the `IOS_ENABLE_APPLE_SIGNIN` plugin variable at plugin installation time:

    cordova plugin add cordova-plugin-firebasex-auth --variable IOS_ENABLE_APPLE_SIGNIN=true

**Parameters**:

-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {string} locale - (Android only) the language to display Apple's Sign-in screen in.
    -   Defaults to "en" (English) if not specified.
    -   See [the Apple documentation](https://developer.apple.com/documentation/signinwithapplejs/incorporating_sign_in_with_apple_into_other_platforms###2112) for a list of supported locales.
    -   The value is ignored on iOS which uses the locale of the device to determine the display language.

Example usage:

```javascript
FirebasexAuth.authenticateUserWithApple(
    function (credential) {
        FirebasexAuth.signInWithCredential(
            credential,
            function () {
                console.log("Successfully signed in");
            },
            function (error) {
                console.error("Failed to sign in", error);
            }
        );
    },
    function (error) {
        console.error("Failed to authenticate with Apple: " + error);
    },
    "en_GB"
);
```

### iOS

To use Sign In with Apple in your iOS app you need to do the following:

-   Configure your app for Sign In with Apple as outlined in the [Firebase documentation's "Before you begin" section](https://firebase.google.com/docs/auth/ios/apple#before-you-begin)
-   After adding the `cordova-ios` platform, open the project workspace in Xcode (`platforms/ios/YourApp.xcworkspace`) and add the "Sign In with Apple" capability in the "Signing & Capabilities section"
    -   Note: AFAIK there is currently no way to automate the addition of this capability

### Android

To use Sign In with Apple in your Android app you need to do the following:

-   Configure your app for Sign In with Apple as outlined in the [Firebase documentation's "Before you begin" section](https://firebase.google.com/docs/auth/android/apple#before-you-begin)

## authenticateUserWithMicrosoft

Authenticates the user with a Microsoft account using Sign In with OAuth to obtain a credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

-   See [Firebase documentation "Authenticate Using Microsoft" section](https://firebase.google.com/docs/auth/web/microsoft-oauth)

**Parameters**:

-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
-   {function} error - callback function which will be passed a {string} error message as an argument
-   {string} locale - (Android only) the language to display Microsoft's Sign-in screen in.
    -   Defaults to "en" (English) if not specified.
    -   See [the Microsoft documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/msal-localization#supported-languages) for a list of supported locales.
    -   The value is ignored on iOS which uses the locale of the device to determine the display language.

Example usage:

```javascript
FirebasexAuth.authenticateUserWithMicrosoft(
    function (credential) {
        FirebasexAuth.signInWithCredential(
            credential,
            function () {
                console.log("Successfully signed in");
            },
            function (error) {
                console.error("Failed to sign in", error);
            }
        );
    },
    function (error) {
        console.error("Failed to authenticate with Microsoft: " + error);
    },
    "en_GB"
);
```

## authenticateUserWithFacebook

Authenticates the user with a Facebook account using a Facebook access token to obtain a Firebase credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

-   Requires a 3rd party plugin such as [cordova-plugin-facebook-connect](https://github.com/cordova-plugin-facebook-connect/cordova-plugin-facebook-connect) to obtain the access token via the Facebook SDK.
-   See the "Before you begin" sections for pre-requisites for using Facebook authentication in your app:
    -   [Android](https://firebase.google.com/docs/auth/android/facebook-login#before_you_begin)
    -   [iOS](https://firebase.google.com/docs/auth/ios/facebook-login#before_you_begin)

**Parameters**:

-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
facebookConnectPlugin.login(
    ["public_profile"],
    function (userData) {
        var accessToken = userData.authResponse.accessToken;
        FirebasexAuth.authenticateUserWithFacebook(
            accessToken,
            function (credential) {
                FirebasexAuth.signInWithCredential(
                    credential,
                    function () {
                        console.log("Successfully signed in with Facebook");
                    },
                    function (error) {
                        console.error("Failed to sign in with Facebook", error);
                    }
                );
            },
            function (error) {
                console.error("Failed to authenticate with Facebook", error);
            }
        );
    },
    function (error) {
        console.error("Failed to login to Facebook", error);
    }
);
```

## authenticateUserWithOAuth

Authenticates the user with an OpenID Connect (OIDC) compliant provider to obtain a credential that can be used to sign the user in/link to an existing user account/reauthenticate the user.

-   You must configure your OIDC provider in the Firebase console before using this method as outlined in the [Firebase documentation](https://firebase.google.com/docs/auth/web/openid-connect);
-   See Firebase documentation "Authenticate Using OpenID Connect" sections for [Android](https://firebase.google.com/docs/auth/android/openid-connect) and [iOS](https://firebase.google.com/docs/auth/ios/openid-connect) for more info.

**Parameters**:

-   {function} success - callback function to pass {object} credentials to as an argument. The credential object has the following properties:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
var providerId = "oidc.provider";
var customParameters = {
    login_hint: "user@domain.com",
};
var scopes = ["openid", "profile", "email"];

FirebasexAuth.authenticateUserWithOAuth(
    function (credential) {
        console.log("Successfully authenticated with oAuth provider");
        FirebasexAuth.signInWithCredential(
            credential,
            function () {
                console.log("Successfully signed in");
            },
            function (error) {
                console.error("Failed to sign in", error);
            }
        );
    },
    function (error) {
        console.error("Failed to authenticate with oAuth provider: " + error);
    },
    providerId,
    customParameters,
    scopes
);
```

## signInWithCredential

Signs the user into Firebase with credentials obtained via an authentication method such as `verifyPhoneNumber()` or `authenticateUserWithGoogle()`.
See the [Android-](https://firebase.google.com/docs/auth/android/phone-auth#sign-in-the-user) and [iOS](https://firebase.google.com/docs/auth/ios/phone-auth#sign-in-the-user-with-the-verification-code)-specific Firebase documentation for more info.

**Parameters**:

-   {object} credential - a credential object returned by the success callback of an authentication method; may have the following keys:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
        Present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `true`, or if another authentication method was used such as `authenticateUserWithGoogle()`.
    -   {boolean} instantVerification - true if an Android device and instant verification or auto-retrieval was used to verify the user.
        If true, you do not need to provide a user-entered verification.
        -   Only present if the credential was obtained via `verifyPhoneNumber()`
    -   {string} verificationId - the verification ID to accompany the user-entered verification code from the SMS.
        -   Only present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`.
    -   {string} code - if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`, you must set this to the activation code value as entered by the user from the received SMS message.
-   {function} success - callback function to call on successful sign-in using credentials
-   {function} error - callback function which will be passed a {string} error message as an argument
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
function signInWithCredential(credential) {
    FirebasexAuth.signInWithCredential(
        credential,
        function () {
            console.log("Successfully signed in");
        },
        function (error, secondFactors) {
            if (
                error === "Second factor required" &&
                typeof secondFactors !== "undefined"
            ) {
                handleSecondFactorAuthentation(secondFactors); // you need to implement this
            } else {
                console.error("Failed to sign in", error);
            }
        }
    );
}
```

## linkUserWithCredential

Links an existing Firebase user account with credentials obtained via an authentication method such as `verifyPhoneNumber()` or `authenticateUserWithGoogle()`.
See the [Android-](https://firebase.google.com/docs/auth/android/account-linking) and [iOS](https://firebase.google.com/docs/auth/ios/account-linking)-specific Firebase documentation for more info.

**Parameters**:

-   {object} credential - a credential object returned by the success callback of an authentication method; may have the following keys:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
        Present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `true`, or if another authentication method was used such as `authenticateUserWithGoogle()`.
    -   {boolean} instantVerification - true if an Android device and instant verification or auto-retrieval was used to verify the user.
        If true, you do not need to provide a user-entered verification.
        -   Only present if the credential was obtained via `verifyPhoneNumber()`
    -   {string} verificationId - the verification ID to accompany the user-entered verification code from the SMS.
        -   Only present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`.
    -   {string} code - if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`, you must set this to the activation code value as entered by the user from the received SMS message.
-   {function} success - callback function to call on successful linking using credentials
-   {function} error - callback function which will be passed a {string} error message as an argument
    -   If the error is due to the user account requiring multi-factor authentication, a second {array} argument will be passed containing a list of enrolled factors.
        -   A factor should be selected and used for second factor verification - see [verifySecondAuthFactor](#verifysecondauthfactor) for more on this.

Example usage:

```javascript
function linkUserWithCredential(credential) {
    FirebasexAuth.linkUserWithCredential(
        credential,
        function () {
            console.log("Successfully linked");
        },
        function (error, secondFactors) {
            if (
                error === "Second factor required" &&
                typeof secondFactors !== "undefined"
            ) {
                handleSecondFactorAuthentation(secondFactors); // you need to implement this
            } else {
                console.error("Failed to link", error);
            }
        }
    );
}
```

## reauthenticateWithCredential

Reauthenticates the currently signed in user with credentials obtained via an authentication method such as `verifyPhoneNumber()` or `authenticateUserWithGoogle()`.

**Parameters**:

-   {object} credential - a credential object returned by the success callback of an authentication method; may have the following keys:
    -   {string} id - the identifier of a native credential object which can be used for signing in the user.
        Present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `true`, or if another authentication method was used such as `authenticateUserWithGoogle()`.
    -   {boolean} instantVerification - true if an Android device and instant verification or auto-retrieval was used to verify the user.
        If true, you do not need to provide a user-entered verification.
        -   Only present if the credential was obtained via `verifyPhoneNumber()`
    -   {string} verificationId - the verification ID to accompany the user-entered verification code from the SMS.
        -   Only present if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`.
    -   {string} code - if the credential was obtained via `verifyPhoneNumber()` and `instantVerification` is `false`, you must set this to the activation code value as entered by the user from the received SMS message.
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
FirebasexAuth.reauthenticateWithCredential(
    credential,
    function () {
        console.log("Successfully reauthenticated");
    },
    function (error, secondFactors) {
        if (
            error === "Second factor required" &&
            typeof secondFactors !== "undefined"
        ) {
            handleSecondFactorAuthentation(secondFactors); // you need to implement this
        } else {
            console.error("Failed to reauthenticate", error);
        }
    }
);
```

## unlinkUserWithProvider

Unlinks an existing Firebase user account with the specified provider ID.
See the [Android-](https://firebase.google.com/docs/auth/android/account-linking#unlink-an-auth-provider-from-a-user-account) and [iOS](https://firebase.google.com/docs/auth/ios/account-linking#unlink-an-auth-provider-from-a-user-account)-specific Firebase documentation for more info.

**Parameters**:

-   {string} providerId - ID of provider to unlink from user account
-   {function} success - callback function to call on successful unlinking of provider
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
var providerId = "microsoft.com";
FirebasexAuth.unlinkUserWithProvider(
    providerId,
    function () {
        console.log("Successfully unlinked");
    },
    function (error) {
        console.error("Failed to unlink", error);
    }
);
```

## registerAuthStateChangeListener

Registers a Javascript function to invoke when Firebase Authentication state changes between user signed in/signed out.

**Parameters**:

-   {function} fn - callback function to invoke when authentication state changes
    -   Will be a passed a single boolean argument which is `true` if user just signed in and `false` if user just signed out.

Example usage:

```javascript
FirebasexAuth.registerAuthStateChangeListener(function (userSignedIn) {
    console.log(
        "Auth state changed: User signed " + (userSignedIn ? "in" : "out")
    );
});
```

## registerAuthIdTokenChangeListener

Registers a Javascript function to invoke when Firebase Authentication ID token changes.

This can be invoked in the following circumstances:

-   When a user signs in
-   When the current user signs out
-   When the current user changes
-   When there is a change in the current user's token

**Parameters**:

-   {function} fn - callback function to invoke when ID token changes
    -   If token is present, will be a passed a single object argument with a `idToken` and `providerId` keys.
    -   If the token is not present, the function will be invoked with no arguments.

Example usage:

```javascript
FirebasexAuth.registerAuthIdTokenChangeListener(function (result) {
    if (result) {
        console.log(
            "Auth ID token changed to: " +
                result.idToken +
                "; providerId: " +
                result.providerId
        );
    } else {
        console.log("Auth ID token not present");
    }
});
```

## useAuthEmulator

Instruments your app to talk to the [Firebase Authentication emulator](https://firebase.google.com/docs/emulator-suite/connect_auth).

**Parameters**:

-   {string} host - hostname or IP address of the Authentication emulator.
-   {integer} port - port of the Authentication emulator.
-   {function} success - callback function to call on success
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
FirebasexAuth.useAuthEmulator(
    "localhost",
    9099,
    function () {
        console.log("Using Firebase Authentication emulator");
    },
    function (error) {
        console.error(
            "Failed to enable the Firebase Authentication emulator",
            error
        );
    }
);
```

## getClaims

Returns the entire payload claims of the ID token including the standard reserved claims as well as the custom claims (set by developer via Admin SDK).

**Parameters**:

-   {function} success - callback function to pass claims {object} to as an argument
-   {function} error - callback function which will be passed a {string} error message as an argument

Example usage:

```javascript
FirebasexAuth.getClaims(
    function (claims) {
        // reserved claims
        console.log("email", claims.email);
        console.log("email_verified", claims.email_verified);
        console.log("name", claims.name);
        console.log("user_id", claims.user_id);

        //custom claims
        console.log("exampleClaimA", claims.exampleClaimA);
        console.log("exampleClaimB", claims.exampleClaimB);
    },
    function (error) {
        console.error("Failed to fetch claims", error);
    }
);
```

# Reporting issues

Before reporting an issue with this plugin, please do the following:
- Check the existing [issues](https://github.com/dpa99c/cordova-plugin-firebasex-auth/issues) to see if the issue has already been reported.
- Check the [issue template](https://github.com/dpa99c/cordova-plugin-firebasex-auth/issues/new/choose) and provide all requested information.
- The more information and context you provide, the easier it is for the maintainers to understand the issue and provide a resolution.
