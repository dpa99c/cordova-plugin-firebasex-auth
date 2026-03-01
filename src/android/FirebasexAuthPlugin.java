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

public class FirebasexAuthPlugin extends CordovaPlugin {

    protected static final String TAG = "FirebasexAuthPlugin";
    private static final int GOOGLE_SIGN_IN = 3;

    interface OnReceivePhoneAuthCredential {
        void onCredential(PhoneAuthCredential credential);
    }

    private static FirebasexAuthPlugin instance;

    private Map<String, AuthCredential> authCredentials = new HashMap<String, AuthCredential>();
    private Map<String, OAuthProvider> authProviders = new HashMap<String, OAuthProvider>();
    private MultiFactorResolver multiFactorResolver = null;
    private CredentialManager credentialManager;

    private static CallbackContext authResultCallbackContext;
    private static CallbackContext activityResultCallbackContext;

    private static boolean authStateChangeListenerInitialized = false;
    private static String currentIdToken = null;

    private PhoneAuthProvider.OnVerificationStateChangedCallbacks phoneAuthVerificationCallbacks;

    public static FirebasexAuthPlugin getInstance() {
        return instance;
    }

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

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);
        if (requestCode == GOOGLE_SIGN_IN && activityResultCallbackContext != null) {
            // Legacy Google Sign-In flow (deprecated in favor of Credential Manager)
            activityResultCallbackContext = null;
        }
    }

    @Override
    public void onReset() {
        activityResultCallbackContext = null;
        authResultCallbackContext = null;
    }

    // ===== PHONE AUTH / MFA =====

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

    private String saveAuthCredential(AuthCredential credential) {
        String key = generateId();
        authCredentials.put(key, credential);
        return key;
    }

    private String saveAuthProvider(OAuthProvider provider) {
        String key = generateId();
        authProviders.put(key, provider);
        return key;
    }

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

    private String generateId() {
        Random random = new Random();
        String key;
        do {
            key = String.valueOf(random.nextInt(100000));
        } while (authCredentials.containsKey(key) || authProviders.containsKey(key));
        return key;
    }

    // ===== AUTH TASK OUTCOME HANDLING =====

    private void handleAuthTaskOutcome(Task<AuthResult> task, final CallbackContext callbackContext) {
        task.addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                .addOnFailureListener(new AuthResultOnFailureListener(callbackContext));
    }

    private void handleAuthResultSuccess(AuthResult authResult, CallbackContext callbackContext) {
        callbackContext.success();
    }

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

    private void sendPluginResult(CallbackContext callbackContext, JSONObject body, boolean keepCallback) {
        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK, body);
        pluginResult.setKeepCallback(keepCallback);
        callbackContext.sendPluginResult(pluginResult);
    }

    private void handleExceptionWithContext(Exception e, CallbackContext callbackContext) {
        String msg = e.getMessage();
        Log.e(TAG, msg, e);
        callbackContext.error(msg);
    }

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
