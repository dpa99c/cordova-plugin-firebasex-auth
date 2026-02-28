var exec = require('cordova/exec');

var SERVICE = 'FirebasexAuthPlugin';

// Internal callbacks
exports._onAuthStateChange = function(userSignedIn) {
    if (exports._authStateChangeCallback) {
        exports._authStateChangeCallback(userSignedIn);
    }
};

exports._onAuthIdTokenChange = function(userSignedIn) {
    if (exports._idTokenChangeCallback) {
        exports._idTokenChangeCallback(userSignedIn);
    }
};

// Auth error result wrapper
function handleAuthErrorResult(resolve, reject) {
    return function(error) {
        try {
            if (typeof error === 'string') {
                error = JSON.parse(error);
            }
            if (error && error.code === 'auth/multi-factor-auth-required' && error.secondFactors) {
                // Parse secondFactors if it's a string
                if (typeof error.secondFactors === 'string') {
                    error.secondFactors = JSON.parse(error.secondFactors);
                }
            }
        } catch (e) {
            // Not JSON, leave as-is
        }
        reject(error);
    };
}

function ensureBoolean(value) {
    if (typeof value === 'string') {
        return value === 'true' || value === '1';
    }
    return !!value;
}

// Phone / MFA
exports.verifyPhoneNumber = function(success, error, phoneNumber, timeOutDuration, fakeVerificationCode, requireSmsValidation) {
    var args = [phoneNumber];
    if (typeof timeOutDuration !== 'undefined') args.push(timeOutDuration);
    if (typeof fakeVerificationCode !== 'undefined') args.push(fakeVerificationCode);
    if (typeof requireSmsValidation !== 'undefined') args.push(requireSmsValidation);
    exec(success, error, SERVICE, 'verifyPhoneNumber', args);
};

exports.enrollSecondAuthFactor = function(success, error, phoneNumber, displayName) {
    exec(success, error, SERVICE, 'enrollSecondAuthFactor', [phoneNumber, displayName]);
};

exports.verifySecondAuthFactor = function(success, error, verificationId, code) {
    exec(success, error, SERVICE, 'verifySecondAuthFactor', [verificationId, code]);
};

exports.listEnrolledSecondAuthFactors = function(success, error) {
    exec(success, error, SERVICE, 'listEnrolledSecondAuthFactors', []);
};

exports.unenrollSecondAuthFactor = function(success, error, selectedIndex) {
    exec(success, error, SERVICE, 'unenrollSecondAuthFactor', [selectedIndex]);
};

// Language
exports.setLanguageCode = function(success, error, lang) {
    exec(success, error, SERVICE, 'setLanguageCode', [lang]);
};

// Email/Password
exports.createUserWithEmailAndPassword = function(success, error, email, password) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'createUserWithEmailAndPassword', [email, password]);
};

exports.signInUserWithEmailAndPassword = function(success, error, email, password) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'signInUserWithEmailAndPassword', [email, password]);
};

exports.authenticateUserWithEmailAndPassword = function(success, error, email, password) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithEmailAndPassword', [email, password]);
};

// Custom token & anonymous
exports.signInUserWithCustomToken = function(success, error, customToken) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'signInUserWithCustomToken', [customToken]);
};

exports.signInUserAnonymously = function(success, error) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'signInUserAnonymously', []);
};

// OAuth Providers
exports.authenticateUserWithGoogle = function(success, error, clientId, options) {
    var args = [clientId];
    if (options) args.push(options);
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithGoogle', args);
};

exports.authenticateUserWithApple = function(success, error, locale) {
    var args = [];
    if (typeof locale !== 'undefined') args.push(locale);
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithApple', args);
};

exports.authenticateUserWithMicrosoft = function(success, error, locale) {
    var args = [];
    if (typeof locale !== 'undefined') args.push(locale);
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithMicrosoft', args);
};

exports.authenticateUserWithFacebook = function(success, error, accessToken) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithFacebook', [accessToken]);
};

exports.authenticateUserWithOAuth = function(success, error, providerId, options) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'authenticateUserWithOAuth', [providerId, options]);
};

// Credential operations
exports.signInWithCredential = function(success, error, credential) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'signInWithCredential', [credential]);
};

exports.linkUserWithCredential = function(success, error, credential) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'linkUserWithCredential', [credential]);
};

exports.reauthenticateWithCredential = function(success, error, credential) {
    exec(success, handleAuthErrorResult(success, error), SERVICE, 'reauthenticateWithCredential', [credential]);
};

exports.unlinkUserWithProvider = function(success, error, providerId) {
    exec(success, error, SERVICE, 'unlinkUserWithProvider', [providerId]);
};

// Session
exports.isUserSignedIn = function(success, error) {
    exec(success, error, SERVICE, 'isUserSignedIn', []);
};

exports.signOutUser = function(success, error) {
    exec(success, error, SERVICE, 'signOutUser', []);
};

exports.getCurrentUser = function(success, error) {
    exec(function(user) {
        if (user && typeof user.emailIsVerified !== 'undefined') {
            user.emailIsVerified = ensureBoolean(user.emailIsVerified);
        }
        success(user);
    }, error, SERVICE, 'getCurrentUser', []);
};

exports.reloadCurrentUser = function(success, error) {
    exec(function(user) {
        if (user && typeof user.emailIsVerified !== 'undefined') {
            user.emailIsVerified = ensureBoolean(user.emailIsVerified);
        }
        success(user);
    }, error, SERVICE, 'reloadCurrentUser', []);
};

// User management
exports.updateUserProfile = function(success, error, profile) {
    exec(success, error, SERVICE, 'updateUserProfile', [profile]);
};

exports.updateUserEmail = function(success, error, email) {
    exec(success, error, SERVICE, 'updateUserEmail', [email]);
};

exports.sendUserEmailVerification = function(success, error, actionCodeSettings) {
    var args = [];
    if (actionCodeSettings) args.push(actionCodeSettings);
    exec(success, error, SERVICE, 'sendUserEmailVerification', args);
};

exports.verifyBeforeUpdateEmail = function(success, error, email, actionCodeSettings) {
    var args = [email];
    if (actionCodeSettings) args.push(actionCodeSettings);
    exec(success, error, SERVICE, 'verifyBeforeUpdateEmail', args);
};

exports.updateUserPassword = function(success, error, password) {
    exec(success, error, SERVICE, 'updateUserPassword', [password]);
};

exports.sendUserPasswordResetEmail = function(success, error, email) {
    exec(success, error, SERVICE, 'sendUserPasswordResetEmail', [email]);
};

exports.deleteUser = function(success, error) {
    exec(success, error, SERVICE, 'deleteUser', []);
};

// Auth state listeners
exports.registerAuthStateChangeListener = function(fn) {
    exports._authStateChangeCallback = fn;
};

exports.registerAuthIdTokenChangeListener = function(fn) {
    exports._idTokenChangeCallback = fn;
};

// Config
exports.useAuthEmulator = function(success, error, host, port) {
    exec(success, error, SERVICE, 'useAuthEmulator', [host, port]);
};

exports.getClaims = function(success, error) {
    exec(success, error, SERVICE, 'getClaims', []);
};
