var exec = require('cordova/exec');

var SERVICE = 'FirebasexAuthPlugin';

var ensureBooleanFn = function (callback) {
    return function (result) {
        callback(ensureBoolean(result));
    }
};

var ensureBoolean = function (value) {
    if (value === "true") {
        value = true;
    } else if (value === "false") {
        value = false;
    }
    return !!value;
};

var handleAuthErrorResult = function (errorCallback) {
    return function (result) {
        var errorMessage, secondFactors;
        if (typeof result === 'object') {
            errorMessage = result.errorMessage;
            secondFactors = result.secondFactors;
        } else {
            errorMessage = result;
        }
        errorCallback(errorMessage, secondFactors);
    }
};

var onAuthStateChangeCallback = function () { };
var onAuthIdTokenChangeCallback = function () { };

/***********************
 * Protected internals
 ***********************/
exports._onAuthStateChange = function (userSignedIn) {
    onAuthStateChangeCallback(userSignedIn);
};

exports._onAuthIdTokenChange = function (token) {
    onAuthIdTokenChangeCallback(token);
};

// Phone / MFA
exports.verifyPhoneNumber = function (success, error, phoneNumber, opts) {
    if (typeof opts !== 'object') opts = {};
    exec(function (credential) {
        if (typeof credential === 'object') {
            credential.instantVerification = ensureBoolean(credential.instantVerification);
        }
        success(credential);
    }, error, SERVICE, "verifyPhoneNumber", [phoneNumber, opts]);
};

exports.enrollSecondAuthFactor = function (success, error, number, opts) {
    if (typeof opts !== 'object') opts = {};
    if (!opts.displayName) {
        var s_number = number + '',
            last4Digits = s_number.slice(-4),
            firstDigits = s_number.slice(0, -4);
        opts.displayName = firstDigits.replace(/[0-9]/g, '*') + last4Digits;
    }
    exec(success, error, SERVICE, "enrollSecondAuthFactor", [number, opts]);
};

exports.verifySecondAuthFactor = function (success, error, params, opts) {
    if (typeof params !== 'object') return error("'params' object must be specified");
    if (typeof opts !== 'object') opts = {};
    exec(success, error, SERVICE, "verifySecondAuthFactor", [params, opts]);
};

exports.listEnrolledSecondAuthFactors = function (success, error) {
    exec(success, error, SERVICE, "listEnrolledSecondAuthFactors", []);
};

exports.unenrollSecondAuthFactor = function (success, error, selectedIndex) {
    exec(success, error, SERVICE, "unenrollSecondAuthFactor", [selectedIndex]);
};

// Language
exports.setLanguageCode = function (lang, success, error) {
    exec(success, error, SERVICE, "setLanguageCode", [lang]);
};

// Email/Password
exports.createUserWithEmailAndPassword = function (email, password, success, error) {
    exec(success, handleAuthErrorResult(error), SERVICE, "createUserWithEmailAndPassword", [email, password]);
};

exports.signInUserWithEmailAndPassword = function (email, password, success, error) {
    exec(success, handleAuthErrorResult(error), SERVICE, "signInUserWithEmailAndPassword", [email, password]);
};

exports.authenticateUserWithEmailAndPassword = function (email, password, success, error) {
    exec(success, handleAuthErrorResult(error), SERVICE, "authenticateUserWithEmailAndPassword", [email, password]);
};

// Custom token & anonymous
exports.signInUserWithCustomToken = function (customToken, success, error) {
    exec(success, handleAuthErrorResult(error), SERVICE, "signInUserWithCustomToken", [customToken]);
};

exports.signInUserAnonymously = function (success, error) {
    exec(success, error, SERVICE, "signInUserAnonymously");
};

// OAuth Providers
exports.authenticateUserWithGoogle = function (clientId, success, error, options) {
    if (typeof options !== 'object') options = {};
    if (options.signIn === undefined) options.signIn = false;
    exec(success, error, SERVICE, "authenticateUserWithGoogle", [clientId, options]);
};

exports.authenticateUserWithApple = function (success, error, locale) {
    exec(success, error, SERVICE, "authenticateUserWithApple", [locale]);
};

exports.authenticateUserWithMicrosoft = function (success, error, locale) {
    exec(success, error, SERVICE, "authenticateUserWithMicrosoft", [locale]);
};

exports.authenticateUserWithFacebook = function (accessToken, success, error) {
    exec(success, error, SERVICE, "authenticateUserWithFacebook", [accessToken]);
};

exports.authenticateUserWithOAuth = function (success, error, providerId, customParameters, scopes) {
    if (typeof providerId !== 'string') return error("'providerId' must be a string");
    exec(success, error, SERVICE, "authenticateUserWithOAuth", [providerId, customParameters, scopes]);
};

// Credential operations
exports.signInWithCredential = function (credential, success, error) {
    if (typeof credential !== 'object') return error("'credential' must be an object");
    exec(success, handleAuthErrorResult(error), SERVICE, "signInWithCredential", [credential]);
};

exports.linkUserWithCredential = function (credential, success, error) {
    if (typeof credential !== 'object') return error("'credential' must be an object");
    exec(success, handleAuthErrorResult(error), SERVICE, "linkUserWithCredential", [credential]);
};

exports.reauthenticateWithCredential = function (credential, success, error) {
    if (typeof credential !== 'object') return error("'credential' must be an object");
    exec(success, handleAuthErrorResult(error), SERVICE, "reauthenticateWithCredential", [credential]);
};

exports.unlinkUserWithProvider = function (providerId, success, error) {
    if (typeof providerId !== 'string') return error("'providerId' must be a string");
    exec(success, handleAuthErrorResult(error), SERVICE, "unlinkUserWithProvider", [providerId]);
};

// Session
exports.isUserSignedIn = function (success, error) {
    exec(ensureBooleanFn(success), error, SERVICE, "isUserSignedIn", []);
};

exports.signOutUser = function (success, error) {
    exec(ensureBooleanFn(success), error, SERVICE, "signOutUser", []);
};

exports.getCurrentUser = function (success, error) {
    exec(function (user) {
        user.emailIsVerified = ensureBoolean(user.emailIsVerified);
        success(user);
    }, error, SERVICE, "getCurrentUser", []);
};

exports.reloadCurrentUser = function (success, error) {
    exec(function (user) {
        user.emailIsVerified = ensureBoolean(user.emailIsVerified);
        success(user);
    }, error, SERVICE, "reloadCurrentUser", []);
};

// User management
exports.updateUserProfile = function (profile, success, error) {
    if (typeof profile !== 'object') return error("'profile' must be an object with keys 'name' and/or 'photoUri'");
    exec(success, error, SERVICE, "updateUserProfile", [profile]);
};

exports.updateUserEmail = function (email, success, error) {
    if (typeof email !== 'string' || !email) return error("'email' must be a valid email address");
    exec(success, error, SERVICE, "updateUserEmail", [email]);
};

exports.sendUserEmailVerification = function (actionCodeSettings, success, error) {
    exec(success, error, SERVICE, "sendUserEmailVerification", [actionCodeSettings]);
};

exports.verifyBeforeUpdateEmail = function (email, success, error) {
    if (typeof email !== 'string' || !email) return error("'email' must be a valid email address");
    exec(success, error, SERVICE, "verifyBeforeUpdateEmail", [email]);
};

exports.updateUserPassword = function (password, success, error) {
    if (typeof password !== 'string' || !password) return error("'password' must be a valid string");
    exec(success, error, SERVICE, "updateUserPassword", [password]);
};

exports.sendUserPasswordResetEmail = function (email, success, error) {
    if (typeof email !== 'string' || !email) return error("'email' must be a valid email address");
    exec(success, error, SERVICE, "sendUserPasswordResetEmail", [email]);
};

exports.deleteUser = function (success, error) {
    exec(success, error, SERVICE, "deleteUser", []);
};

// Auth state listeners
exports.registerAuthStateChangeListener = function (fn) {
    if (typeof fn !== "function") throw "The specified argument must be a function";
    onAuthStateChangeCallback = fn;
};

exports.registerAuthIdTokenChangeListener = function (fn) {
    if (typeof fn !== "function") throw "The specified argument must be a function";
    onAuthIdTokenChangeCallback = fn;
};

// Config
exports.useAuthEmulator = function (host, port, success, error) {
    exec(success, error, SERVICE, "useAuthEmulator", [host, port]);
};

exports.getClaims = function (success, error) {
    exec(success, error, SERVICE, "getClaims", []);
};
