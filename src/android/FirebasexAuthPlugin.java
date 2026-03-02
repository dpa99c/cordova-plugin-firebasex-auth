package org.apache.cordova.firebasex;

import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.exceptions.GetCredentialException;

import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.android.libraries.identity.googleid.GetGoogleIdOption;
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential;

import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.ActionCodeSettings;
import com.google.firebase.auth.AuthCredential;
import com.google.firebase.auth.AuthResult;
import com.google.firebase.auth.EmailAuthProvider;
import com.google.firebase.auth.FacebookAuthProvider;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthInvalidCredentialsException;
import com.google.firebase.auth.FirebaseAuthMultiFactorException;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.FirebaseUserMetadata;
import com.google.firebase.auth.GetTokenResult;
import com.google.firebase.auth.GoogleAuthProvider;
import com.google.firebase.auth.MultiFactorAssertion;
import com.google.firebase.auth.MultiFactorInfo;
import com.google.firebase.auth.MultiFactorResolver;
import com.google.firebase.auth.MultiFactorSession;
import com.google.firebase.auth.OAuthCredential;
import com.google.firebase.auth.OAuthProvider;
import com.google.firebase.auth.PhoneAuthCredential;
import com.google.firebase.auth.PhoneAuthOptions;
import com.google.firebase.auth.PhoneAuthProvider;
import com.google.firebase.auth.PhoneMultiFactorGenerator;
import com.google.firebase.auth.PhoneMultiFactorInfo;
import com.google.firebase.auth.UserInfo;
import com.google.firebase.auth.UserProfileChangeRequest;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Cordova plugin providing Firebase Authentication functionality on Android.
 * <p>
 * Supports multiple authentication methods including email/password, phone number,
 * anonymous sign-in, custom tokens, and OAuth providers (Google via Credential Manager,
 * Apple, Microsoft, Facebook, and generic OAuth). Also provides multi-factor authentication
 * (MFA) enrollment and verification, credential management, user profile operations,
 * and auth state change listeners.
 * </p>
 *
 * @see <a href="https://firebase.google.com/docs/auth/android/start">Firebase Auth Android docs</a>
 */
public class FirebasexAuthPlugin extends CordovaPlugin {

    /** Log tag for this plugin. */
    protected static final String TAG = "FirebasexAuthPlugin";

    /** Request code for the legacy Google Sign-In activity result flow (deprecated in favor of Credential Manager). */
    private static final int GOOGLE_SIGN_IN = 3;

    /**
     * Callback interface for receiving a {@link PhoneAuthCredential} after phone number verification
     * completes with instant verification.
     */
    interface OnReceivePhoneAuthCredential {
        void onCredential(PhoneAuthCredential credential);
    }

    /** Singleton instance of this plugin. */
    private static FirebasexAuthPlugin instance;

    /** Map of stored auth credentials keyed by a generated string ID. Used to pass credentials between JS and native. */
    private Map<String, AuthCredential> authCredentials = new HashMap<String, AuthCredential>();

    /** Map of stored OAuth providers keyed by a generated string ID. Used for pending OAuth flows. */
    private Map<String, OAuthProvider> authProviders = new HashMap<String, OAuthProvider>();

    /** Resolver for multi-factor authentication challenges. Set when an MFA challenge is triggered. */
    private MultiFactorResolver multiFactorResolver = null;

    /** Android Credential Manager instance for Google Sign-In via the modern Credential Manager API. */
    private CredentialManager credentialManager;

    /** Callback context for auth result operations that span multiple native calls. */
    private static CallbackContext authResultCallbackContext;

    /** Callback context for activity result operations (legacy Google Sign-In flow). */
    private static CallbackContext activityResultCallbackContext;

    /** Whether the auth state change listener has been initialized. */
    private static boolean authStateChangeListenerInitialized = false;

    /** The current cached ID token, used to detect token changes. */
    private static String currentIdToken = null;

    /** Callbacks for phone number verification state changes. */
    private PhoneAuthProvider.OnVerificationStateChangedCallbacks phoneAuthVerificationCallbacks;

    /**
     * Returns the singleton instance of this plugin.
     * @return The plugin instance, or null if not yet initialized.
     */
    public static FirebasexAuthPlugin getInstance() {
        return instance;
    }

    /**
     * Initializes the plugin: creates the Credential Manager, registers the Firebase Auth
     * state change listener and ID token listener that forward events to JavaScript.
     */
    @Override
    protected void pluginInitialize() {
        instance = this;
        Log.d(TAG, "Starting FirebasexAuth plugin");

        this.cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    credentialManager = CredentialManager.create(cordova.getActivity().getApplicationContext());

                    AuthStateListener authStateListener = new AuthStateListener();
                    FirebaseAuth.getInstance().addAuthStateListener(authStateListener);

                    IdTokenListener idTokenListener = new IdTokenListener();
                    FirebaseAuth.getInstance().addIdTokenListener(idTokenListener);
                } catch (Exception e) {
                    Log.e(TAG, "Error initializing auth plugin: " + e.getMessage(), e);
                }
            }
        });
    }

    /**
     * Dispatches a Cordova action to the corresponding plugin method.
     * Handles 30+ actions covering authentication, MFA, OAuth, credential operations,
     * user management, and configuration.
     *
     * @param action          The action name from the JavaScript interface.
     * @param args            The JSON arguments array from JavaScript.
     * @param callbackContext The callback context for returning results to JavaScript.
     * @return true if the action was recognized and handled, false otherwise.
     * @throws JSONException If there is an error parsing the JSON arguments.
     */
    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        try {
            switch (action) {
                case "verifyPhoneNumber":
                    this.verifyPhoneNumber(callbackContext, args);
                    break;
                case "enrollSecondAuthFactor":
                    this.enrollSecondAuthFactor(callbackContext, args);
                    break;
                case "verifySecondAuthFactor":
                    this.verifySecondAuthFactor(callbackContext, args);
                    break;
                case "listEnrolledSecondAuthFactors":
                    this.listEnrolledSecondAuthFactors(callbackContext, args);
                    break;
                case "unenrollSecondAuthFactor":
                    this.unenrollSecondAuthFactor(callbackContext, args);
                    break;
                case "setLanguageCode":
                    this.setLanguageCode(callbackContext, args);
                    break;
                case "createUserWithEmailAndPassword":
                    this.createUserWithEmailAndPassword(callbackContext, args);
                    break;
                case "signInUserWithEmailAndPassword":
                    this.signInUserWithEmailAndPassword(callbackContext, args);
                    break;
                case "authenticateUserWithEmailAndPassword":
                    this.authenticateUserWithEmailAndPassword(callbackContext, args);
                    break;
                case "signInUserWithCustomToken":
                    this.signInUserWithCustomToken(callbackContext, args);
                    break;
                case "signInUserAnonymously":
                    this.signInUserAnonymously(callbackContext);
                    break;
                case "authenticateUserWithGoogle":
                    this.authenticateUserWithGoogle(callbackContext, args);
                    break;
                case "authenticateUserWithApple":
                    this.authenticateUserWithApple(callbackContext, args);
                    break;
                case "authenticateUserWithMicrosoft":
                    this.authenticateUserWithMicrosoft(callbackContext, args);
                    break;
                case "authenticateUserWithFacebook":
                    this.authenticateUserWithFacebook(callbackContext, args);
                    break;
                case "authenticateUserWithOAuth":
                    this.authenticateUserWithOAuth(callbackContext, args);
                    break;
                case "signInWithCredential":
                    this.signInWithCredential(callbackContext, args);
                    break;
                case "linkUserWithCredential":
                    this.linkUserWithCredential(callbackContext, args);
                    break;
                case "reauthenticateWithCredential":
                    this.reauthenticateWithCredential(callbackContext, args);
                    break;
                case "unlinkUserWithProvider":
                    this.unlinkUserWithProvider(callbackContext, args);
                    break;
                case "isUserSignedIn":
                    this.isUserSignedIn(callbackContext, args);
                    break;
                case "signOutUser":
                    this.signOutUser(callbackContext, args);
                    break;
                case "getCurrentUser":
                    this.getCurrentUser(callbackContext, args);
                    break;
                case "reloadCurrentUser":
                    this.reloadCurrentUser(callbackContext, args);
                    break;
                case "updateUserProfile":
                    this.updateUserProfile(callbackContext, args);
                    break;
                case "updateUserEmail":
                    this.updateUserEmail(callbackContext, args);
                    break;
                case "sendUserEmailVerification":
                    this.sendUserEmailVerification(callbackContext, args);
                    break;
                case "verifyBeforeUpdateEmail":
                    this.verifyBeforeUpdateEmail(callbackContext, args);
                    break;
                case "updateUserPassword":
                    this.updateUserPassword(callbackContext, args);
                    break;
                case "sendUserPasswordResetEmail":
                    this.sendUserPasswordResetEmail(callbackContext, args);
                    break;
                case "deleteUser":
                    this.deleteUser(callbackContext, args);
                    break;
                case "useAuthEmulator":
                    this.useAuthEmulator(callbackContext, args);
                    break;
                case "getClaims":
                    this.getClaims(callbackContext, args);
                    break;
                case "getProviderData":
                    this.getProviderData(callbackContext, args);
                    break;
                default:
                    callbackContext.error("Invalid action: " + action);
                    return false;
            }
        } catch (Exception e) {
            handleExceptionWithContext(e, callbackContext);
            return false;
        }
        return true;
    }

    /**
     * Handles activity results from legacy Google Sign-In flow.
     * Note: The modern Credential Manager flow does not use activity results.
     *
     * @param requestCode The request code originally supplied to startActivityForResult().
     * @param resultCode  The result code returned by the child activity.
     * @param intent      The data returned from the child activity.
     */
    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);
        if (requestCode == GOOGLE_SIGN_IN && activityResultCallbackContext != null) {
            // Legacy Google Sign-In flow (deprecated in favor of Credential Manager)
            activityResultCallbackContext = null;
        }
    }

    /**
     * Cleans up callback contexts when the plugin is reset (e.g. page navigation).
     */
    @Override
    public void onReset() {
        activityResultCallbackContext = null;
        authResultCallbackContext = null;
    }

    // ===== PHONE AUTH / MFA =====

    /**
     * Verifies a phone number for phone-based authentication.
     * <p>
     * Supports instant verification (auto-retrieval on Android), manual SMS code entry,
     * fake verification codes for testing, and configurable timeouts.
     * </p>
     *
     * @param callbackContext The callback for returning verification results.
     * @param args            JSON array: [phoneNumber, opts]. opts may contain:
     *                        <ul>
     *                          <li>{@code timeOutDuration} - Timeout in seconds (default 30)</li>
     *                          <li>{@code fakeVerificationCode} - Testing code for Firebase Auth emulator</li>
     *                          <li>{@code requireSmsValidation} - Force SMS even if instant verification is available</li>
     *                        </ul>
     */
    private void verifyPhoneNumber(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    phoneAuthVerificationCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                        @Override
                        public void onVerificationCompleted(PhoneAuthCredential credential) {
                            try {
                                String id = saveAuthCredential(credential);
                                JSONObject returnResults = new JSONObject();
                                returnResults.put("instantVerification", true);
                                returnResults.put("id", id);
                                sendPluginResult(callbackContext, returnResults, true);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }

                        @Override
                        public void onVerificationFailed(com.google.firebase.FirebaseException e) {
                            try {
                                String errorMsg;
                                if (e instanceof FirebaseAuthInvalidCredentialsException) {
                                    errorMsg = "Invalid phone number";
                                } else if (e instanceof com.google.firebase.FirebaseTooManyRequestsException) {
                                    errorMsg = "The SMS quota for the project has been exceeded";
                                } else {
                                    errorMsg = e.getMessage();
                                }
                                callbackContext.error(errorMsg);
                            } catch (Exception ex) {
                                handleExceptionWithContext(ex, callbackContext);
                            }
                        }

                        @Override
                        public void onCodeSent(String verificationId, PhoneAuthProvider.ForceResendingToken forceResendingToken) {
                            try {
                                JSONObject returnResults = new JSONObject();
                                returnResults.put("verificationId", verificationId);
                                returnResults.put("instantVerification", false);
                                sendPluginResult(callbackContext, returnResults, true);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    };

                    String number = args.getString(0);
                    JSONObject opts = args.getJSONObject(1);

                    int timeOutDuration = 30;
                    if (opts.has("timeOutDuration")) {
                        timeOutDuration = opts.getInt("timeOutDuration");
                    }

                    String fakeVerificationCode = null;
                    if (opts.has("fakeVerificationCode")) {
                        fakeVerificationCode = opts.getString("fakeVerificationCode");
                    }
                    boolean requireSmsValidation = false;
                    if (opts.has("requireSmsValidation")) {
                        requireSmsValidation = opts.getBoolean("requireSmsValidation");
                    };

                    PhoneAuthOptions.Builder optionsBuilder = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
                            .setPhoneNumber(number)
                            .setTimeout((long) timeOutDuration, TimeUnit.SECONDS)
                            .setActivity(cordova.getActivity())
                            .setCallbacks(phoneAuthVerificationCallbacks);

                    if (fakeVerificationCode != null) {
                        // For testing: force verification code
                        FirebaseAuth.getInstance().getFirebaseAuthSettings()
                                .setAutoRetrievedSmsCodeForPhoneNumber(number, fakeVerificationCode);
                    }

                    if (requireSmsValidation) {
                        optionsBuilder.requireSmsValidation(true);
                    }

                    PhoneAuthProvider.verifyPhoneNumber(optionsBuilder.build());
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Enrolls a phone number as a second authentication factor for the current user.
     * <p>
     * Initiates a multi-factor enrollment session. If the provided credential contains
     * a verification ID and code, enrollment completes immediately. Otherwise, an SMS
     * verification is sent and the verification ID is returned for manual code entry.
     * </p>
     *
     * @param callbackContext The callback for returning enrollment results.
     * @param args            JSON array: [phoneNumber, opts]. opts may contain:
     *                        <ul>
     *                          <li>{@code displayName} - Display name for this factor</li>
     *                          <li>{@code credential} - Optional credential with verificationId/code for immediate enrollment</li>
     *                        </ul>
     */
    private void enrollSecondAuthFactor(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    // Extract plugin inputs
                    String phoneNumber = args.getString(0);
                    JSONObject opts = args.getJSONObject(1);

                    int timeOutDuration = 30;
                    if (opts.has("timeOutDuration")) {
                        timeOutDuration = opts.getInt("timeOutDuration");
                    }

                    String fakeVerificationCode = null;
                    if (opts.has("fakeVerificationCode")) {
                        fakeVerificationCode = opts.getString("fakeVerificationCode");
                    }
                    boolean requireSmsValidation = false;
                    if (opts.has("requireSmsValidation")) {
                        requireSmsValidation = opts.getBoolean("requireSmsValidation");
                    }

                    String displayName = opts.getString("displayName");

                    String verificationId = null;
                    String verificationCode = null;
                    if (opts.has("credential")) {
                        JSONObject jsonCredential = opts.getJSONObject("credential");
                        if (jsonCredential.has("verificationId") && jsonCredential.has("code")) {
                            verificationId = jsonCredential.getString("verificationId");
                            verificationCode = jsonCredential.getString("code");
                        } else {
                            callbackContext.error("'verificationId' and/or 'code' properties not found on 'credential' object");
                            return;
                        }
                    }

                    // Handler for credential enrollment
                    final String finalDisplayName = displayName;
                    OnReceivePhoneAuthCredential credentialReceiver = new OnReceivePhoneAuthCredential() {
                        public void onCredential(PhoneAuthCredential credential) {
                            try {
                                MultiFactorAssertion multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(credential);
                                user.getMultiFactor()
                                        .enroll(multiFactorAssertion, finalDisplayName)
                                        .addOnCompleteListener(new OnCompleteListener<Void>() {
                                            @Override
                                            public void onComplete(@NonNull Task<Void> task) {
                                                if (task.isSuccessful()) {
                                                    callbackContext.success();
                                                } else {
                                                    handleExceptionWithContext(task.getException(), callbackContext);
                                                }
                                            }
                                        });
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    };

                    // Arguments contain ID & code from manual SMS verification, so use this for enrollment
                    if (verificationId != null) {
                        PhoneAuthCredential credential = PhoneAuthProvider.getCredential(verificationId, verificationCode);
                        credentialReceiver.onCredential(credential);
                        return;
                    }

                    // Create phone verification callbacks
                    phoneAuthVerificationCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                        @Override
                        public void onVerificationCompleted(@NonNull PhoneAuthCredential credential) {
                            try {
                                credentialReceiver.onCredential(credential);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }

                        @Override
                        public void onVerificationFailed(@NonNull com.google.firebase.FirebaseException e) {
                            try {
                                String errorMsg;
                                if (e instanceof FirebaseAuthInvalidCredentialsException) {
                                    errorMsg = "Invalid phone number";
                                } else if (e instanceof com.google.firebase.FirebaseTooManyRequestsException) {
                                    errorMsg = "The SMS quota for the project has been exceeded";
                                } else {
                                    errorMsg = e.getMessage();
                                }
                                callbackContext.error(errorMsg);
                            } catch (Exception ex) {
                                handleExceptionWithContext(ex, callbackContext);
                            }
                        }

                        @Override
                        public void onCodeSent(@NonNull String verificationId, @NonNull PhoneAuthProvider.ForceResendingToken token) {
                            try {
                                JSONObject returnResults = new JSONObject();
                                returnResults.put("verificationId", verificationId);
                                sendPluginResult(callbackContext, returnResults, true);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    };

                    // Rescope variables for lambda
                    final String finalFakeVerificationCode = fakeVerificationCode;
                    final int finalTimeOutDuration = timeOutDuration;
                    final boolean finalRequireSmsValidation = requireSmsValidation;

                    // Get multi-factor session
                    user.getMultiFactor().getSession().addOnCompleteListener(new OnCompleteListener<MultiFactorSession>() {
                        @Override
                        public void onComplete(@NonNull Task<MultiFactorSession> task) {
                            try {
                                if (!task.isSuccessful()) {
                                    handleExceptionWithContext(task.getException(), callbackContext);
                                    return;
                                }
                                MultiFactorSession multiFactorSession = task.getResult();

                                if (finalFakeVerificationCode != null && !finalFakeVerificationCode.equals("null")) {
                                    FirebaseAuth.getInstance().getFirebaseAuthSettings()
                                            .setAutoRetrievedSmsCodeForPhoneNumber(phoneNumber, finalFakeVerificationCode);
                                }

                                PhoneAuthOptions phoneAuthOptions = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
                                        .setPhoneNumber(phoneNumber)
                                        .setTimeout((long) finalTimeOutDuration, TimeUnit.SECONDS)
                                        .setMultiFactorSession(multiFactorSession)
                                        .setActivity(cordova.getActivity())
                                        .setCallbacks(phoneAuthVerificationCallbacks)
                                        .requireSmsValidation(finalRequireSmsValidation)
                                        .build();
                                PhoneAuthProvider.verifyPhoneNumber(phoneAuthOptions);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Verifies a second authentication factor during an MFA challenge.
     * <p>
     * Resolves a pending multi-factor sign-in by providing the SMS verification code.
     * Can use either a {@code selectedIndex} parameter (to pick a factor from the resolver's hints)
     * or a {@code credential} object with verificationId/code.
     * </p>
     *
     * @param callbackContext The callback for returning verification results.
     * @param args            JSON array: [params, opts]. params may contain:
     *                        <ul>
     *                          <li>{@code selectedIndex} - Index of the factor to verify</li>
     *                          <li>{@code credential} - Object with verificationId and code</li>
     *                        </ul>
     */
    private void verifySecondAuthFactor(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    if (multiFactorResolver == null) {
                        callbackContext.error("No multi-factor challenge exists to resolve");
                        return;
                    }

                    // Required params
                    JSONObject params = args.getJSONObject(0);
                    int selectedIndex = -1;
                    if (params.has("selectedIndex")) {
                        selectedIndex = params.getInt("selectedIndex");
                        if (selectedIndex < 0) {
                            callbackContext.error("Selected index value (" + selectedIndex + ") must be a positive integer");
                            return;
                        } else if (selectedIndex + 1 > multiFactorResolver.getHints().size()) {
                            callbackContext.error("Selected index value (" + selectedIndex + ") exceeds the number of enrolled factors (" + multiFactorResolver.getHints().size() + ")");
                            return;
                        }
                    }

                    String verificationId = null;
                    String verificationCode = null;
                    if (params.has("credential")) {
                        JSONObject jsonCredential = params.getJSONObject("credential");
                        if (jsonCredential.has("verificationId") && jsonCredential.has("code")) {
                            verificationId = jsonCredential.getString("verificationId");
                            verificationCode = jsonCredential.getString("code");
                        } else {
                            callbackContext.error("'verificationId' and/or 'code' properties not found on 'credential' object");
                            return;
                        }
                    }

                    if (selectedIndex == -1 && verificationId == null) {
                        callbackContext.error("Neither 'selectedIndex' or 'credential' properties found on 'params' object - either one must be specified");
                        return;
                    }

                    // Extract optional params
                    JSONObject opts = args.getJSONObject(1);

                    int timeOutDuration = 30;
                    if (opts.has("timeOutDuration")) {
                        timeOutDuration = opts.getInt("timeOutDuration");
                    }

                    String fakeVerificationCode = null;
                    String phoneNumber = null;
                    if (opts.has("fakeVerificationCode")) {
                        fakeVerificationCode = opts.getString("fakeVerificationCode");
                        if (opts.has("phoneNumber")) {
                            phoneNumber = opts.getString("phoneNumber");
                        } else {
                            callbackContext.error("'phoneNumber' property must also be specified on 'opts' object when 'fakeVerificationCode' is specified");
                            return;
                        }
                    }

                    boolean requireSmsValidation = false;
                    if (opts.has("requireSmsValidation")) {
                        requireSmsValidation = opts.getBoolean("requireSmsValidation");
                    }

                    // Handler for credential resolution
                    OnReceivePhoneAuthCredential credentialReceiver = new OnReceivePhoneAuthCredential() {
                        public void onCredential(PhoneAuthCredential credential) {
                            try {
                                MultiFactorAssertion multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(credential);
                                multiFactorResolver
                                        .resolveSignIn(multiFactorAssertion)
                                        .addOnCompleteListener(new OnCompleteListener<AuthResult>() {
                                            @Override
                                            public void onComplete(@NonNull Task<AuthResult> task) {
                                                try {
                                                    if (task.isSuccessful()) {
                                                        multiFactorResolver = null;
                                                        callbackContext.success();
                                                    } else {
                                                        handleAuthResultFailure(task.getException(), callbackContext);
                                                    }
                                                } catch (Exception e) {
                                                    handleExceptionWithContext(e, callbackContext);
                                                }
                                            }
                                        });
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    };

                    // Arguments contain ID & code from manual SMS verification
                    if (verificationId != null) {
                        PhoneAuthCredential credential = PhoneAuthProvider.getCredential(verificationId, verificationCode);
                        credentialReceiver.onCredential(credential);
                        return;
                    }

                    // Phone verification flow
                    phoneAuthVerificationCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                        @Override
                        public void onVerificationCompleted(PhoneAuthCredential credential) {
                            try {
                                credentialReceiver.onCredential(credential);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }

                        @Override
                        public void onVerificationFailed(com.google.firebase.FirebaseException e) {
                            try {
                                String errorMsg;
                                if (e instanceof com.google.firebase.FirebaseTooManyRequestsException) {
                                    errorMsg = "The SMS quota for the project has been exceeded";
                                } else {
                                    errorMsg = e.getMessage();
                                }
                                callbackContext.error(errorMsg);
                            } catch (Exception ex) {
                                handleExceptionWithContext(ex, callbackContext);
                            }
                        }

                        @Override
                        public void onCodeSent(String verificationId, PhoneAuthProvider.ForceResendingToken token) {
                            try {
                                JSONObject returnResults = new JSONObject();
                                returnResults.put("verificationId", verificationId);
                                sendPluginResult(callbackContext, returnResults, true);
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }
                    };

                    // Rescope variables for lambda
                    final int finalSelectedIndex = selectedIndex;
                    final String finalFakeVerificationCode = fakeVerificationCode;
                    final String finalPhoneNumber = phoneNumber;
                    final int finalTimeOutDuration = timeOutDuration;
                    final boolean finalRequireSmsValidation = requireSmsValidation;

                    if (finalFakeVerificationCode != null && !finalFakeVerificationCode.equals("null")) {
                        FirebaseAuth.getInstance().getFirebaseAuthSettings()
                                .setAutoRetrievedSmsCodeForPhoneNumber(finalPhoneNumber, finalFakeVerificationCode);
                    }

                    PhoneMultiFactorInfo selectedHint = (PhoneMultiFactorInfo) multiFactorResolver.getHints().get(finalSelectedIndex);

                    PhoneAuthOptions phoneAuthOptions = PhoneAuthOptions.newBuilder()
                            .setMultiFactorSession(multiFactorResolver.getSession())
                            .setMultiFactorHint(selectedHint)
                            .setTimeout((long) finalTimeOutDuration, TimeUnit.SECONDS)
                            .setCallbacks(phoneAuthVerificationCallbacks)
                            .setActivity(cordova.getActivity())
                            .requireSmsValidation(finalRequireSmsValidation)
                            .build();
                    PhoneAuthProvider.verifyPhoneNumber(phoneAuthOptions);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Lists the second authentication factors enrolled for the current user.
     *
     * @param callbackContext The callback returning a JSON array of enrolled factors.
     *                        Each factor contains: index, phoneNumber, and optionally displayName.
     * @param args            Not used.
     */
    private void listEnrolledSecondAuthFactors(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    List<MultiFactorInfo> enrolledFactors = user.getMultiFactor().getEnrolledFactors();
                    JSONArray result = parseEnrolledSecondFactorsToJson(enrolledFactors);
                    callbackContext.success(result);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Removes an enrolled second authentication factor from the current user.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [selectedIndex] - The integer index of the factor to remove.
     */
    private void unenrollSecondAuthFactor(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    int selectedIndex = args.getInt(0);

                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    List<MultiFactorInfo> enrolledFactors = user.getMultiFactor().getEnrolledFactors();
                    if (selectedIndex < 0 || selectedIndex >= enrolledFactors.size()) {
                        callbackContext.error("Invalid factor index");
                        return;
                    }

                    MultiFactorInfo selectedFactor = enrolledFactors.get(selectedIndex);
                    user.getMultiFactor().unenroll(selectedFactor)
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== LANGUAGE =====

    /**
     * Sets the language code for Firebase Auth operations such as SMS verification messages.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [languageCode] - The language code string (e.g. "en", "fr").
     */
    private void setLanguageCode(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String lang = args.getString(0);
                    FirebaseAuth.getInstance().setLanguageCode(lang);
                    callbackContext.success();
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== EMAIL/PASSWORD =====

    /**
     * Creates a new user account with the specified email address and password.
     * Also signs in the user upon successful creation.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [email, password].
     */
    private void createUserWithEmailAndPassword(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String email = args.getString(0);
                    String password = args.getString(1);
                    FirebaseAuth.getInstance().createUserWithEmailAndPassword(email, password)
                            .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                            .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Signs in an existing user with email and password.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [email, password].
     */
    private void signInUserWithEmailAndPassword(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String email = args.getString(0);
                    String password = args.getString(1);
                    FirebaseAuth.getInstance().signInWithEmailAndPassword(email, password)
                            .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                            .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Creates an email/password credential without signing in.
     * The credential is stored natively and its ID is returned for later use
     * with {@link #signInWithCredential}, {@link #linkUserWithCredential}, etc.
     *
     * @param callbackContext The callback returning a JSON object with {@code instantVerification} and {@code id}.
     * @param args            JSON array: [email, password].
     */
    private void authenticateUserWithEmailAndPassword(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String email = args.getString(0);
                    String password = args.getString(1);
                    AuthCredential credential = EmailAuthProvider.getCredential(email, password);
                    String key = saveAuthCredential(credential);
                    JSONObject result = new JSONObject();
                    result.put("instantVerification", true);
                    result.put("id", key);
                    callbackContext.success(result);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== CUSTOM TOKEN & ANONYMOUS =====

    private void signInUserWithCustomToken(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String customToken = args.getString(0);
                    FirebaseAuth.getInstance().signInWithCustomToken(customToken)
                            .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                            .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Signs in the user anonymously. If an anonymous user already exists, that user is returned.
     *
     * @param callbackContext The callback for returning the result.
     */
    private void signInUserAnonymously(final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseAuth.getInstance().signInAnonymously()
                            .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                            .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== OAUTH PROVIDERS =====

    /**
     * Authenticates the user with Google Sign-In using the Android Credential Manager API.
     * If the {@code signIn} option is true, the user is signed in to Firebase immediately;
     * otherwise, the credential is stored and its ID returned for later use.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [clientId, options]. Options may contain:
     *                        <ul>
     *                          <li>{@code signIn} - If true, signs in immediately (default: true)</li>
     *                        </ul>
     */
    private void authenticateUserWithGoogle(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String clientId = args.getString(0);
                    boolean signIn = true;
                    if (args.length() > 1 && !args.isNull(1)) {
                        JSONObject options = args.getJSONObject(1);
                        if (options.has("signIn")) {
                            signIn = options.getBoolean("signIn");
                        }
                    }

                    signInWithCredentialManager(callbackContext, clientId, signIn);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Performs Google Sign-In using the Android Credential Manager API.
     * Constructs a {@link GetGoogleIdOption} request, prompts the user to select an account,
     * and either signs in to Firebase or returns the credential for later use.
     *
     * @param callbackContext The callback for returning the result.
     * @param clientId        The Google OAuth web client ID.
     * @param signIn          If true, signs in immediately; if false, stores credential and returns its ID.
     */
    private void signInWithCredentialManager(final CallbackContext callbackContext, String clientId, boolean signIn) {
        try {
            GetGoogleIdOption googleIdOption = new GetGoogleIdOption.Builder()
                    .setFilterByAuthorizedAccounts(false)
                    .setServerClientId(clientId)
                    .setAutoSelectEnabled(true)
                    .build();

            GetCredentialRequest request = new GetCredentialRequest.Builder()
                    .addCredentialOption(googleIdOption)
                    .build();

            credentialManager.getCredentialAsync(
                    cordova.getActivity(),
                    request,
                    new android.os.CancellationSignal(),
                    Executors.newSingleThreadExecutor(),
                    new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                        @Override
                        public void onResult(GetCredentialResponse result) {
                            try {
                                if (result.getCredential().getData() != null) {
                                    GoogleIdTokenCredential googleIdTokenCredential = GoogleIdTokenCredential.createFrom(result.getCredential().getData());
                                    String idToken = googleIdTokenCredential.getIdToken();
                                    AuthCredential firebaseCredential = GoogleAuthProvider.getCredential(idToken, null);

                                    if (signIn) {
                                        handleAuthTaskOutcome(
                                                FirebaseAuth.getInstance().signInWithCredential(firebaseCredential),
                                                callbackContext
                                        );
                                    } else {
                                        String key = saveAuthCredential(firebaseCredential);
                                        JSONObject returnResult = new JSONObject();
                                        returnResult.put("instantVerification", true);
                                        returnResult.put("id", key);
                                        returnResult.put("idToken", idToken);
                                        callbackContext.success(returnResult);
                                    }
                                }
                            } catch (Exception e) {
                                handleExceptionWithContext(e, callbackContext);
                            }
                        }

                        @Override
                        public void onError(@NonNull GetCredentialException e) {
                            callbackContext.error("Credential Manager error: " + e.getMessage());
                        }
                    }
            );
        } catch (Exception e) {
            handleExceptionWithContext(e, callbackContext);
        }
    }

    /**
     * Authenticates the user with Apple Sign-In via Firebase OAuthProvider.
     * Passes an optional locale as a custom parameter.
     *
     * @param callbackContext The callback for returning the credential result.
     * @param args            JSON array: [locale] - Optional locale string.
     */
    private void authenticateUserWithApple(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String locale = args.getString(0);
                    Map<String, String> customParameters = new HashMap<>();
                    if (locale != null) {
                        customParameters.put("locale", locale);
                    }
                    authenticateUserWithOAuthInternal(callbackContext, "apple.com", customParameters, null);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Authenticates the user with Microsoft Sign-In via Firebase OAuthProvider.
     * Sets "prompt" to "consent" and passes an optional locale as custom parameters.
     *
     * @param callbackContext The callback for returning the credential result.
     * @param args            JSON array: [locale] - Optional locale string.
     */
    private void authenticateUserWithMicrosoft(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String locale = args.getString(0);
                    Map<String, String> customParameters = new HashMap<>();
                    customParameters.put("prompt", "consent");
                    if (locale != null) {
                        customParameters.put("locale", locale);
                    }
                    authenticateUserWithOAuthInternal(callbackContext, "microsoft.com", customParameters, null);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Authenticates the user with Facebook using a pre-obtained access token.
     * Creates a Facebook credential and stores it natively, returning its ID.
     *
     * @param callbackContext The callback returning a JSON object with {@code instantVerification} and {@code id}.
     * @param args            JSON array: [accessToken] - The Facebook access token.
     */
    private void authenticateUserWithFacebook(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String accessToken = args.getString(0);
                    AuthCredential credential = FacebookAuthProvider.getCredential(accessToken);
                    String id = saveAuthCredential(credential);
                    JSONObject returnResults = new JSONObject();
                    returnResults.put("instantVerification", true);
                    returnResults.put("id", id);
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, returnResults));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Authenticates the user with a generic OAuth provider via Firebase OAuthProvider.
     * Supports custom parameters and scopes for any OAuth provider.
     *
     * @param callbackContext The callback for returning the credential result.
     * @param args            JSON array: [providerId, customParameters, scopes].
     */
    private void authenticateUserWithOAuth(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String providerId = args.getString(0);
                    JSONObject customParametersJson = args.getJSONObject(1);
                    JSONArray scopesJson = args.getJSONArray(2);

                    Map<String, String> customParameters = null;
                    List<String> scopes = null;

                    if (customParametersJson != null) {
                        Iterator<String> keys = customParametersJson.keys();
                        customParameters = new HashMap<>();
                        while (keys.hasNext()) {
                            String key = keys.next();
                            String value = customParametersJson.getString(key);
                            customParameters.put(key, value);
                        }
                    }

                    if (scopesJson != null) {
                        scopes = new ArrayList<>();
                        for (int i = 0; i < scopesJson.length(); i++) {
                            scopes.add(scopesJson.getString(i));
                        }
                    }

                    authenticateUserWithOAuthInternal(callbackContext, providerId, customParameters, scopes);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Internal implementation for OAuth provider authentication.
     * Builds an {@link OAuthProvider} with the specified parameters and scopes,
     * checks for a pending auth result, and stores the provider for later use.
     *
     * @param callbackContext  The callback for returning the result.
     * @param providerId       The OAuth provider ID (e.g. "apple.com", "microsoft.com").
     * @param customParameters Custom OAuth parameters, or null.
     * @param scopes           OAuth scopes to request, or null.
     */
    private void authenticateUserWithOAuthInternal(final CallbackContext callbackContext, final String providerId, final Map<String, String> customParameters, final List<String> scopes) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    OAuthProvider.Builder provider = OAuthProvider.newBuilder(providerId);
                    if (customParameters != null) {
                        for (Map.Entry<String, String> entry : customParameters.entrySet()) {
                            provider.addCustomParameter(entry.getKey(), entry.getValue());
                        }
                    }
                    if (scopes != null) {
                        provider.setScopes(scopes);
                    }

                    Task<AuthResult> pending = FirebaseAuth.getInstance().getPendingAuthResult();
                    if (pending != null) {
                        callbackContext.error("Auth result is already pending");
                        pending
                                .addOnSuccessListener(new AuthResultOnSuccessListener())
                                .addOnFailureListener(new AuthResultOnFailureListener());
                    } else {
                        String id = saveAuthProvider(provider.build());
                        JSONObject returnResults = new JSONObject();
                        returnResults.put("instantVerification", true);
                        returnResults.put("id", id);
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, returnResults));
                    }
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== CREDENTIAL OPERATIONS =====

    /**
     * Signs in the user using a previously stored native credential.
     * The credential is retrieved using an ID or constructed from verificationId/code.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [credential] - Object with {@code id} or {@code verificationId}/{@code code}.
     */
    private void signInWithCredential(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    AuthCredential credential = obtainAuthCredential(args);
                    if (credential == null) {
                        callbackContext.error("Failed to obtain auth credential from provided arguments");
                        return;
                    }
                    handleAuthTaskOutcome(
                            FirebaseAuth.getInstance().signInWithCredential(credential),
                            callbackContext
                    );
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Links a credential to the currently signed-in user, adding an additional sign-in method.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [credential] - Object with {@code id} or {@code verificationId}/{@code code}.
     */
    private void linkUserWithCredential(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    AuthCredential credential = obtainAuthCredential(args);
                    if (credential == null) {
                        callbackContext.error("Failed to obtain auth credential from provided arguments");
                        return;
                    }
                    handleAuthTaskOutcome(
                            user.linkWithCredential(credential),
                            callbackContext
                    );
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Re-authenticates the current user with a fresh credential.
     * Required before sensitive operations like email/password updates or account deletion.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [credential] - Object with {@code id} or {@code verificationId}/{@code code}.
     */
    private void reauthenticateWithCredential(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    AuthCredential credential = obtainAuthCredential(args);
                    if (credential == null) {
                        callbackContext.error("Failed to obtain auth credential from provided arguments");
                        return;
                    }
                    handleAuthTaskOutcome(
                            user.reauthenticateAndRetrieveData(credential),
                            callbackContext
                    );
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Unlinks a provider from the currently signed-in user.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [providerId] - The provider ID to unlink (e.g. "google.com").
     */
    private void unlinkUserWithProvider(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    String providerId = args.getString(0);
                    user.unlink(providerId)
                            .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                            .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== SESSION =====

    /**
     * Checks whether a user is currently signed in.
     *
     * @param callbackContext The callback returning a boolean result.
     * @param args            Not used.
     */
    private void isUserSignedIn(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, user != null));
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Signs out the currently authenticated user.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            Not used.
     */
    private void signOutUser(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseAuth.getInstance().signOut();
                    callbackContext.success();
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== USER INFO =====

    /**
     * Gets the profile information for the currently signed-in user.
     *
     * @param callbackContext The callback returning a JSON object with user profile data.
     * @param args            Not used.
     * @see #extractAndReturnUserInfo(CallbackContext, FirebaseUser)
     */
    private void getCurrentUser(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    extractAndReturnUserInfo(callbackContext, user);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Reloads the current user's profile from the server, then returns the refreshed data.
     *
     * @param callbackContext The callback returning a JSON object with refreshed user profile data.
     * @param args            Not used.
     */
    private void reloadCurrentUser(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    final FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    user.reload().addOnCompleteListener(new OnCompleteListener<Void>() {
                        @Override
                        public void onComplete(@NonNull Task<Void> task) {
                            if (task.isSuccessful()) {
                                FirebaseUser reloadedUser = FirebaseAuth.getInstance().getCurrentUser();
                                if (reloadedUser != null) {
                                    extractAndReturnUserInfo(callbackContext, reloadedUser);
                                } else {
                                    callbackContext.error("User not found after reload");
                                }
                            } else {
                                callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                            }
                        }
                    });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Extracts comprehensive user profile information and returns it to JavaScript.
     * <p>
     * Includes display name, email (with verification status), phone number, photo URL,
     * UID, anonymous status, creation/sign-in timestamps, linked provider data,
     * ID token, and sign-in provider ID.
     * </p>
     *
     * @param callbackContext The callback for sending the user info JSON object.
     * @param user            The Firebase user to extract info from.
     */
    private void extractAndReturnUserInfo(final CallbackContext callbackContext, final FirebaseUser user) {
        try {
            final JSONObject returnResults = new JSONObject();
            returnResults.put("name", user.getDisplayName());
            returnResults.put("email", user.getEmail());
            returnResults.put("emailIsVerified", user.isEmailVerified());
            returnResults.put("phoneNumber", user.getPhoneNumber());
            returnResults.put("photoUrl", user.getPhotoUrl() != null ? user.getPhotoUrl().toString() : null);
            returnResults.put("uid", user.getUid());
            returnResults.put("isAnonymous", user.isAnonymous());

            FirebaseUserMetadata metadata = user.getMetadata();
            if (metadata != null) {
                returnResults.put("creationTimestamp", metadata.getCreationTimestamp());
                returnResults.put("lastSignInTimestamp", metadata.getLastSignInTimestamp());
            }

            JSONArray providers = new JSONArray();
            for (UserInfo profile : user.getProviderData()) {
                JSONObject provider = new JSONObject();
                provider.put("providerId", profile.getProviderId());
                provider.put("uid", profile.getUid());
                provider.put("displayName", profile.getDisplayName());
                provider.put("email", profile.getEmail());
                provider.put("phoneNumber", profile.getPhoneNumber());
                provider.put("photoUrl", profile.getPhotoUrl() != null ? profile.getPhotoUrl().toString() : null);
                providers.put(provider);
            }
            returnResults.put("providers", providers);

            user.getIdToken(true).addOnSuccessListener(new OnSuccessListener<GetTokenResult>() {
                @Override
                public void onSuccess(GetTokenResult result) {
                    try {
                        String idToken = result.getToken();
                        returnResults.put("idToken", idToken);
                        returnResults.put("providerId", result.getSignInProvider());
                        callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.OK, returnResults));
                    } catch (Exception e) {
                        handleExceptionWithContext(e, callbackContext);
                    }
                }
            }).addOnFailureListener(new OnFailureListener() {
                @Override
                public void onFailure(@NonNull Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            });
        } catch (Exception e) {
            handleExceptionWithContext(e, callbackContext);
        }
    }

    /**
     * Gets the linked provider data for the currently signed-in user.
     * Returns a JSON array of provider info objects containing providerId, uid, displayName,
     * email, phoneNumber, and photoUrl.
     *
     * @param callbackContext The callback returning a JSON array of provider info.
     * @param args            Not used.
     */
    private void getProviderData(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    JSONArray providers = new JSONArray();
                    for (UserInfo profile : user.getProviderData()) {
                        JSONObject provider = new JSONObject();
                        provider.put("providerId", profile.getProviderId());
                        provider.put("uid", profile.getUid());
                        provider.put("displayName", profile.getDisplayName());
                        provider.put("email", profile.getEmail());
                        provider.put("phoneNumber", profile.getPhoneNumber());
                        provider.put("photoUrl", profile.getPhotoUrl() != null ? profile.getPhotoUrl().toString() : null);
                        providers.put(provider);
                    }
                    callbackContext.success(providers);
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== USER MANAGEMENT =====

    /**
     * Updates the current user's display name and/or photo URL.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [profile] - Object with optional {@code name} and {@code photoUri}.
     */
    private void updateUserProfile(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    JSONObject profile = args.getJSONObject(0);
                    UserProfileChangeRequest.Builder profileBuilder = new UserProfileChangeRequest.Builder();

                    if (profile.has("name")) {
                        profileBuilder.setDisplayName(profile.getString("name"));
                    }
                    if (profile.has("photoUri")) {
                        profileBuilder.setPhotoUri(android.net.Uri.parse(profile.getString("photoUri")));
                    }

                    user.updateProfile(profileBuilder.build())
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Updates the current user's email address.
     * Sends a verification email to the new address via {@code verifyBeforeUpdateEmail}.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [email] - The new email address.
     */
    private void updateUserEmail(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    String email = args.getString(0);
                    user.verifyBeforeUpdateEmail(email)
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Sends an email verification to the current user's email address.
     * Supports optional {@link ActionCodeSettings} for custom email templates.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [actionCodeSettings] - Optional settings object with:
     *                        {@code url}, {@code handleCodeInApp}, {@code iOS}, {@code android}, {@code dynamicLinkDomain}.
     */
    private void sendUserEmailVerification(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    Task<Void> task;
                    if (args.length() > 0 && !args.isNull(0)) {
                        JSONObject settingsJson = args.getJSONObject(0);
                        ActionCodeSettings.Builder builder = ActionCodeSettings.newBuilder()
                                .setUrl(settingsJson.getString("url"));
                        if (settingsJson.has("handleCodeInApp")) {
                            builder.setHandleCodeInApp(settingsJson.getBoolean("handleCodeInApp"));
                        }
                        if (settingsJson.has("iOS")) {
                            JSONObject ios = settingsJson.getJSONObject("iOS");
                            builder.setIOSBundleId(ios.getString("bundleId"));
                        }
                        if (settingsJson.has("android")) {
                            JSONObject android = settingsJson.getJSONObject("android");
                            builder.setAndroidPackageName(
                                    android.getString("packageName"),
                                    android.optBoolean("installApp", false),
                                    android.optString("minimumVersion", null)
                            );
                        }
                        if (settingsJson.has("dynamicLinkDomain")) {
                            builder.setDynamicLinkDomain(settingsJson.getString("dynamicLinkDomain"));
                        }
                        task = user.sendEmailVerification(builder.build());
                    } else {
                        task = user.sendEmailVerification();
                    }

                    task.addOnCompleteListener(new OnCompleteListener<Void>() {
                        @Override
                        public void onComplete(@NonNull Task<Void> t) {
                            if (t.isSuccessful()) {
                                callbackContext.success();
                            } else {
                                callbackContext.error(Objects.requireNonNull(t.getException()).getMessage());
                            }
                        }
                    });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Sends a verification email to a new email address before updating the user's email.
     * Supports optional {@link ActionCodeSettings} for custom email templates.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [email, actionCodeSettings]. Action code settings
     *                        may contain {@code url}, {@code handleCodeInApp}, {@code dynamicLinkDomain}.
     */
    private void verifyBeforeUpdateEmail(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    String email = args.getString(0);

                    Task<Void> task;
                    if (args.length() > 1 && !args.isNull(1)) {
                        JSONObject settingsJson = args.getJSONObject(1);
                        ActionCodeSettings.Builder builder = ActionCodeSettings.newBuilder()
                                .setUrl(settingsJson.getString("url"));
                        if (settingsJson.has("handleCodeInApp")) {
                            builder.setHandleCodeInApp(settingsJson.getBoolean("handleCodeInApp"));
                        }
                        if (settingsJson.has("dynamicLinkDomain")) {
                            builder.setDynamicLinkDomain(settingsJson.getString("dynamicLinkDomain"));
                        }
                        task = user.verifyBeforeUpdateEmail(email, builder.build());
                    } else {
                        task = user.verifyBeforeUpdateEmail(email);
                    }

                    task.addOnCompleteListener(new OnCompleteListener<Void>() {
                        @Override
                        public void onComplete(@NonNull Task<Void> t) {
                            if (t.isSuccessful()) {
                                callbackContext.success();
                            } else {
                                callbackContext.error(Objects.requireNonNull(t.getException()).getMessage());
                            }
                        }
                    });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Updates the current user's password.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [password] - The new password.
     */
    private void updateUserPassword(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    String password = args.getString(0);
                    user.updatePassword(password)
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Sends a password reset email to the specified email address.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [email] - The email address of the account.
     */
    private void sendUserPasswordResetEmail(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String email = args.getString(0);
                    FirebaseAuth.getInstance().sendPasswordResetEmail(email)
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Deletes the currently signed-in user account.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            Not used.
     */
    private void deleteUser(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }
                    user.delete()
                            .addOnCompleteListener(new OnCompleteListener<Void>() {
                                @Override
                                public void onComplete(@NonNull Task<Void> task) {
                                    if (task.isSuccessful()) {
                                        callbackContext.success();
                                    } else {
                                        callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                                    }
                                }
                            });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== CONFIG =====

    /**
     * Configures Firebase Auth to connect to a local Auth emulator for testing.
     * Must be called before any other auth operations.
     *
     * @param callbackContext The callback for returning the result.
     * @param args            JSON array: [host, port].
     */
    private void useAuthEmulator(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String host = args.getString(0);
                    int port = args.getInt(1);
                    FirebaseAuth.getInstance().useEmulator(host, port);
                    callbackContext.success();
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    /**
     * Retrieves the custom claims from the current user's ID token.
     * Forces a token refresh to get the latest claims.
     *
     * @param callbackContext The callback returning a JSON object with the claims.
     * @param args            Not used.
     */
    private void getClaims(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    user.getIdToken(true).addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
                        @Override
                        public void onComplete(@NonNull Task<GetTokenResult> task) {
                            if (task.isSuccessful()) {
                                Map<String, Object> claims = task.getResult().getClaims();
                                callbackContext.success(new JSONObject(claims));
                            } else {
                                callbackContext.error(Objects.requireNonNull(task.getException()).getMessage());
                            }
                        }
                    });
                } catch (Exception e) {
                    handleExceptionWithContext(e, callbackContext);
                }
            }
        });
    }

    // ===== AUTH CREDENTIAL MANAGEMENT =====

    /**
     * Stores an auth credential in the credentials map and returns its generated key.
     *
     * @param credential The auth credential to store.
     * @return The generated string key for retrieving the credential.
     */
    private String saveAuthCredential(AuthCredential credential) {
        String key = generateId();
        authCredentials.put(key, credential);
        return key;
    }

    /**
     * Stores an OAuth provider in the providers map and returns its generated key.
     *
     * @param provider The OAuth provider to store.
     * @return The generated string key for retrieving the provider.
     */
    private String saveAuthProvider(OAuthProvider provider) {
        String key = generateId();
        authProviders.put(key, provider);
        return key;
    }

    /**
     * Retrieves an auth credential from the stored credentials.
     * Supports two credential formats:
     * <ul>
     *   <li>Object with {@code verificationId} and {@code code} - creates a PhoneAuthProvider credential</li>
     *   <li>Object with {@code id} - retrieves a stored native credential by its key</li>
     * </ul>
     *
     * @param args The JSON arguments containing the credential specification.
     * @return The resolved AuthCredential, or null if not found.
     */
    private AuthCredential obtainAuthCredential(JSONArray args) {
        try {
            JSONObject jsonCredential = args.getJSONObject(0);
            if (jsonCredential.has("verificationId") && jsonCredential.has("code")) {
                Log.d(TAG, "Using specified verificationId and code to authenticate");
                return PhoneAuthProvider.getCredential(jsonCredential.getString("verificationId"), jsonCredential.getString("code"));
            } else if (jsonCredential.has("id") && authCredentials.containsKey(jsonCredential.getString("id"))) {
                Log.d(TAG, "Using native auth credential to authenticate");
                AuthCredential authCredential = authCredentials.get(jsonCredential.getString("id"));
                authCredentials.remove(jsonCredential.getString("id"));
                return authCredential;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error obtaining auth credential: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Retrieves a stored OAuth provider by its key from the JSON arguments.
     *
     * @param args The JSON arguments containing a credential object with an {@code id} field.
     * @return The stored OAuthProvider, or null if not found.
     */
    private OAuthProvider obtainAuthProvider(JSONArray args) {
        try {
            JSONObject jsonProvider = args.getJSONObject(0);
            if (jsonProvider.has("id") && authProviders.containsKey(jsonProvider.getString("id"))) {
                Log.d(TAG, "Using native auth provider to authenticate");
                return authProviders.get(jsonProvider.getString("id"));
            }
        } catch (Exception e) {
            Log.e(TAG, "Error obtaining auth provider: " + e.getMessage(), e);
        }
        return null;
    }

    /**
     * Generates a unique random string ID for credential/provider storage.
     * Ensures no collision with existing keys in both credential and provider maps.
     *
     * @return A unique string key.
     */
    private String generateId() {
        Random random = new Random();
        String key;
        do {
            key = String.valueOf(random.nextInt(100000));
        } while (authCredentials.containsKey(key) || authProviders.containsKey(key));
        return key;
    }

    // ===== AUTH TASK OUTCOME HANDLING =====

    /**
     * Attaches success and failure listeners to an auth task.
     *
     * @param task            The auth task to monitor.
     * @param callbackContext The callback for returning results.
     */
    private void handleAuthTaskOutcome(Task<AuthResult> task, final CallbackContext callbackContext) {
        task.addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
    }

    /**
     * Handles a successful auth result by sending a success plugin result.
     *
     * @param authResult      The successful auth result.
     * @param callbackContext The callback context to send the result to.
     */
    private void handleAuthResultSuccess(AuthResult authResult, CallbackContext callbackContext) {
        callbackContext.success();
    }

    /**
     * Converts a list of enrolled multi-factor infos to a JSON array.
     * Each element contains index, phoneNumber, and optional displayName.
     *
     * @param multiFactorInfoList The list of enrolled multi-factor info objects.
     * @return A JSON array of factor info objects.
     * @throws JSONException If there is an error constructing the JSON.
     */
    private JSONArray parseEnrolledSecondFactorsToJson(List<MultiFactorInfo> multiFactorInfoList) throws JSONException {
        JSONArray secondFactors = new JSONArray();
        for (int i = 0; i < multiFactorInfoList.size(); i++) {
            JSONObject secondFactor = new JSONObject();
            secondFactor.put("index", i);

            PhoneMultiFactorInfo phoneMultiFactorInfo = (PhoneMultiFactorInfo) multiFactorInfoList.get(i);
            secondFactor.put("phoneNumber", phoneMultiFactorInfo.getPhoneNumber());

            String displayName = phoneMultiFactorInfo.getDisplayName();
            if (displayName != null) {
                secondFactor.put("displayName", displayName);
            }
            secondFactors.put(secondFactor);
        }
        return secondFactors;
    }

    /**
     * Handles a failed auth result.
     * <p>
     * Detects specific error types:
     * <ul>
     *   <li>{@link FirebaseAuthInvalidCredentialsException} - Returns "Invalid verification code"</li>
     *   <li>{@link FirebaseAuthMultiFactorException} - Returns a JSON error with the enrolled second factors
     *       and stores the resolver for subsequent MFA verification</li>
     * </ul>
     * </p>
     *
     * @param exception       The auth exception that occurred.
     * @param callbackContext The callback context to send the error to.
     */
    private void handleAuthResultFailure(Exception exception, CallbackContext callbackContext) {
        try {
            if (exception instanceof FirebaseAuthInvalidCredentialsException) {
                callbackContext.error("Invalid verification code");
            } else if (exception instanceof FirebaseAuthMultiFactorException) {
                FirebaseAuthMultiFactorException multiFactorException = (FirebaseAuthMultiFactorException) exception;
                multiFactorResolver = multiFactorException.getResolver();

                JSONObject errorResult = new JSONObject();
                errorResult.put("errorMessage", "Second factor required");

                JSONArray secondFactors = parseEnrolledSecondFactorsToJson(multiFactorResolver.getHints());
                errorResult.put("secondFactors", secondFactors);

                callbackContext.error(errorResult);
            } else {
                callbackContext.error(exception.getMessage());
            }
        } catch (JSONException e) {
            callbackContext.error("Auth error: " + exception.getMessage());
        }
    }

    // ===== AUTH LISTENERS =====

    /**
     * Firebase Auth state change listener that forwards sign-in/sign-out events to JavaScript.
     * Invokes the JavaScript callback {@code FirebasexAuth._onAuthStateChange(isSignedIn)}
     * via the core plugin's global JavaScript executor.
     */
    private class AuthStateListener implements FirebaseAuth.AuthStateListener {
        @Override
        public void onAuthStateChanged(@NonNull FirebaseAuth firebaseAuth) {
            try {
                boolean isSignedIn = firebaseAuth.getCurrentUser() != null;
                String js = "javascript:if(typeof(FirebasexAuth) !== 'undefined' && typeof(FirebasexAuth._onAuthStateChange) === 'function'){FirebasexAuth._onAuthStateChange(" + isSignedIn + ")}";

                FirebasexCorePlugin corePlugin = FirebasexCorePlugin.getInstance();
                if (corePlugin != null) {
                    corePlugin.executeGlobalJavascript(js);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error in AuthStateListener: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Firebase ID token change listener that forwards token change events to JavaScript.
     * Invokes the JavaScript callback {@code FirebasexAuth._onAuthIdTokenChange(isSignedIn)}
     * via the core plugin's global JavaScript executor.
     */
    private class IdTokenListener implements FirebaseAuth.IdTokenListener {
        @Override
        public void onIdTokenChanged(@NonNull FirebaseAuth firebaseAuth) {
            try {
                boolean isSignedIn = firebaseAuth.getCurrentUser() != null;
                String js = "javascript:if(typeof(FirebasexAuth) !== 'undefined' && typeof(FirebasexAuth._onAuthIdTokenChange) === 'function'){FirebasexAuth._onAuthIdTokenChange(" + isSignedIn + ")}";

                FirebasexCorePlugin corePlugin = FirebasexCorePlugin.getInstance();
                if (corePlugin != null) {
                    corePlugin.executeGlobalJavascript(js);
                }
            } catch (Exception e) {
                Log.e(TAG, "Error in IdTokenListener: " + e.getMessage(), e);
            }
        }
    }

    // ===== AUTH RESULT CALLBACKS =====

    /**
     * Success listener for Firebase Auth operations that return an {@link AuthResult}.
     * Delegates to {@link #handleAuthResultSuccess} using either the provided callback context
     * or the fallback {@link #authResultCallbackContext}.
     */
    private class AuthResultOnSuccessListener implements OnSuccessListener<AuthResult> {
        private CallbackContext callbackContext;

        AuthResultOnSuccessListener() {
            this.callbackContext = null;
        }

        AuthResultOnSuccessListener(CallbackContext callbackContext) {
            this.callbackContext = callbackContext;
        }

        @Override
        public void onSuccess(AuthResult authResult) {
            if (callbackContext != null) {
                handleAuthResultSuccess(authResult, callbackContext);
            } else if (authResultCallbackContext != null) {
                handleAuthResultSuccess(authResult, authResultCallbackContext);
            }
        }
    }

    /**
     * Failure listener for Firebase Auth operations.
     * Delegates to {@link #handleAuthResultFailure} using either the provided callback context
     * or the fallback {@link #authResultCallbackContext}.
     */
    private class AuthResultOnFailureListener implements OnFailureListener {
        private CallbackContext callbackContext;

        AuthResultOnFailureListener() {
            this.callbackContext = null;
        }

        AuthResultOnFailureListener(CallbackContext callbackContext) {
            this.callbackContext = callbackContext;
        }

        @Override
        public void onFailure(@NonNull Exception e) {
            if (callbackContext != null) {
                handleAuthResultFailure(e, callbackContext);
            } else if (authResultCallbackContext != null) {
                handleAuthResultFailure(e, authResultCallbackContext);
            }
        }
    }

    // ===== UTILITY METHODS =====

    /**
     * Sends a plugin result with keep-callback option.
     *
     * @param callbackContext The callback context.
     * @param body            The JSON response body.
     * @param keepCallback    Whether to keep the callback for future results.
     */
    private void sendPluginResult(CallbackContext callbackContext, JSONObject body, boolean keepCallback) {
        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, body);
        pluginResult.setKeepCallback(keepCallback);
        callbackContext.sendPluginResult(pluginResult);
    }

    /**
     * Logs an exception and sends the error message back to JavaScript.
     *
     * @param e               The exception that occurred.
     * @param callbackContext The callback context to send the error to.
     */
    private void handleExceptionWithContext(Exception e, CallbackContext callbackContext) {
        String msg = e.getMessage();
        Log.e(TAG, msg, e);
        callbackContext.error(msg);
    }

    /**
     * Reflectively accesses a private field on an object.
     * Used for extracting internal data from Firebase SDK objects when no public API is available.
     *
     * @param obj       The object to read the field from.
     * @param fieldName The name of the private field.
     * @return The field's string value, or null if the field cannot be accessed.
     */
    private String getPrivateField(Object obj, String fieldName) {
        try {
            java.lang.reflect.Field field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            Object value = field.get(obj);
            return value != null ? value.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
