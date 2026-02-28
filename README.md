# cordova-plugin-firebasex-auth

Firebase Authentication module for the modular FirebaseX Cordova plugin suite.

## Dependencies

- `cordova-plugin-firebasex-core` (automatically installed)

## Installation

```bash
cordova plugin add cordova-plugin-firebasex-auth
```

### Plugin Variables

| Variable | Default | Description |
|---|---|---|
| `SETUP_RECAPTCHA_VERIFICATION` | `false` | Set to `true` to add the reversed client ID URL scheme for reCAPTCHA verification (iOS) |
| `IOS_ENABLE_APPLE_SIGNIN` | `false` | Set to `true` to add Apple Sign-In entitlement (iOS) |
| `IOS_GOOGLE_SIGIN_VERSION` | `9.0.0` | Google Sign-In iOS SDK version |

Example with variables:
```bash
cordova plugin add cordova-plugin-firebasex-auth \
  --variable SETUP_RECAPTCHA_VERIFICATION=true \
  --variable IOS_ENABLE_APPLE_SIGNIN=true
```

## API

Access via `FirebasexAuth` global or `require('cordova-plugin-firebasex-auth.FirebasexAuth')`.

### Authentication Methods

- `verifyPhoneNumber(phoneNumber, timeoutDuration, fakeVerificationCode, success, error)` - Verify a phone number
- `enrollSecondAuthFactor(phoneNumber, displayName, success, error)` - Enroll a second auth factor (MFA)
- `verifySecondAuthFactor(verificationId, code, success, error)` - Verify a second auth factor
- `listEnrolledSecondAuthFactors(success, error)` - List enrolled second auth factors
- `unenrollSecondAuthFactor(selectedIndex, success, error)` - Unenroll a second auth factor
- `setLanguageCode(lang, success, error)` - Set the language code for auth operations
- `createUserWithEmailAndPassword(email, password, success, error)` - Create a new user
- `signInUserWithEmailAndPassword(email, password, success, error)` - Sign in with email/password
- `authenticateUserWithEmailAndPassword(email, password, success, error)` - Get credentials without signing in
- `signInUserWithCustomToken(token, success, error)` - Sign in with a custom token
- `signInUserAnonymously(success, error)` - Sign in anonymously
- `authenticateUserWithGoogle(clientId, success, error)` - Authenticate with Google
- `authenticateUserWithApple(success, error)` - Authenticate with Apple
- `authenticateUserWithMicrosoft(locale, success, error)` - Authenticate with Microsoft
- `authenticateUserWithFacebook(accessToken, success, error)` - Authenticate with Facebook
- `authenticateUserWithOAuth(providerId, options, success, error)` - Authenticate with generic OAuth
- `signInWithCredential(credential, success, error)` - Sign in with a stored credential
- `linkUserWithCredential(credential, success, error)` - Link credential to current user
- `reauthenticateWithCredential(credential, success, error)` - Reauthenticate current user
- `unlinkUserWithProvider(providerId, success, error)` - Unlink a provider from current user

### User Management

- `isUserSignedIn(success, error)` - Check if a user is signed in
- `signOutUser(success, error)` - Sign out the current user
- `getCurrentUser(success, error)` - Get current user info
- `reloadCurrentUser(success, error)` - Reload current user from server
- `updateUserProfile(profile, success, error)` - Update user display name/photo
- `updateUserEmail(email, success, error)` - Update user email
- `sendUserEmailVerification(actionCodeSettings, success, error)` - Send verification email
- `verifyBeforeUpdateEmail(email, actionCodeSettings, success, error)` - Verify before updating email
- `updateUserPassword(password, success, error)` - Update user password
- `sendUserPasswordResetEmail(email, success, error)` - Send password reset email
- `deleteUser(success, error)` - Delete the current user

### Listeners & Utilities

- `registerAuthStateChangeListener(fn)` - Register auth state change callback
- `registerAuthIdTokenChangeListener(fn)` - Register ID token change callback
- `useAuthEmulator(host, port, success, error)` - Connect to auth emulator
- `getClaims(success, error)` - Get the current user's custom claims
