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
import com.google.firebase.auth.FirebaseAuthMultiFactorException;
import com.google.firebase.auth.FirebaseUser;
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class FirebasexAuthPlugin extends CordovaPlugin {

    protected static final String TAG = "FirebasexAuthPlugin";
    private static final int GOOGLE_SIGN_IN = 3;

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
                    String number = args.getString(0);
                    int timeOutDuration = 60;
                    if (args.length() > 1 && !args.isNull(1)) {
                        timeOutDuration = args.getInt(1);
                    }
                    String fakeVerificationCode = null;
                    if (args.length() > 2 && !args.isNull(2)) {
                        fakeVerificationCode = args.getString(2);
                    }
                    boolean requireSmsValidation = false;
                    if (args.length() > 3 && !args.isNull(3)) {
                        requireSmsValidation = args.getBoolean(3);
                    }

                    phoneAuthVerificationCallbacks = new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                        @Override
                        public void onVerificationCompleted(PhoneAuthCredential credential) {
                            String key = saveAuthCredential(credential);
                            JSONObject returnResults = new JSONObject();
                            try {
                                returnResults.put("instantVerification", true);
                                returnResults.put("key", key);
                                if (credential.getSmsCode() != null) {
                                    returnResults.put("code", credential.getSmsCode());
                                }
                                String verificationId = getPrivateField(credential, "zza");
                                if (verificationId != null) {
                                    returnResults.put("verificationId", verificationId);
                                }
                            } catch (Exception e) {
                                Log.e(TAG, "Error in onVerificationCompleted: " + e.getMessage(), e);
                            }
                            sendPluginResult(callbackContext, returnResults, true);
                        }

                        @Override
                        public void onVerificationFailed(com.google.firebase.FirebaseException e) {
                            callbackContext.error(e.getMessage());
                        }

                        @Override
                        public void onCodeSent(String verificationId, PhoneAuthProvider.ForceResendingToken forceResendingToken) {
                            JSONObject returnResults = new JSONObject();
                            try {
                                returnResults.put("verificationId", verificationId);
                                returnResults.put("instantVerification", false);
                            } catch (JSONException e) {
                                Log.e(TAG, "Error in onCodeSent: " + e.getMessage(), e);
                            }
                            sendPluginResult(callbackContext, returnResults, true);
                        }
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
                    final String phoneNumber = args.getString(0);
                    final String displayName = args.getString(1);

                    FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                    if (user == null) {
                        callbackContext.error("No user is currently signed in");
                        return;
                    }

                    user.getMultiFactorInfo();
                    user.getMultiFactor().getSession().addOnCompleteListener(new OnCompleteListener<MultiFactorSession>() {
                        @Override
                        public void onComplete(@NonNull Task<MultiFactorSession> task) {
                            if (task.isSuccessful()) {
                                MultiFactorSession multiFactorSession = task.getResult();

                                PhoneAuthOptions phoneAuthOptions = PhoneAuthOptions.newBuilder(FirebaseAuth.getInstance())
                                        .setPhoneNumber(phoneNumber)
                                        .setTimeout(30L, TimeUnit.SECONDS)
                                        .setMultiFactorSession(multiFactorSession)
                                        .setActivity(cordova.getActivity())
                                        .setCallbacks(new PhoneAuthProvider.OnVerificationStateChangedCallbacks() {
                                            @Override
                                            public void onVerificationCompleted(@NonNull PhoneAuthCredential phoneAuthCredential) {
                                                PhoneMultiFactorGenerator.getAssertion(phoneAuthCredential);

                                                MultiFactorAssertion multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(phoneAuthCredential);
                                                FirebaseAuth.getInstance().getCurrentUser().getMultiFactor().enroll(multiFactorAssertion, displayName)
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
                                            }

                                            @Override
                                            public void onVerificationFailed(@NonNull com.google.firebase.FirebaseException e) {
                                                callbackContext.error(e.getMessage());
                                            }

                                            @Override
                                            public void onCodeSent(@NonNull String verificationId, @NonNull PhoneAuthProvider.ForceResendingToken token) {
                                                JSONObject returnResults = new JSONObject();
                                                try {
                                                    returnResults.put("verificationId", verificationId);
                                                } catch (JSONException e) {
                                                    Log.e(TAG, "Error in onCodeSent: " + e.getMessage(), e);
                                                }
                                                sendPluginResult(callbackContext, returnResults, true);
                                            }
                                        })
                                        .requireSmsValidation(true)
                                        .build();

                                PhoneAuthProvider.verifyPhoneNumber(phoneAuthOptions);
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

    private void verifySecondAuthFactor(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String verificationId = args.getString(0);
                    String code = args.getString(1);

                    PhoneAuthCredential credential = PhoneAuthProvider.getCredential(verificationId, code);
                    MultiFactorAssertion multiFactorAssertion = PhoneMultiFactorGenerator.getAssertion(credential);

                    if (multiFactorResolver != null) {
                        multiFactorResolver.resolveSignIn(multiFactorAssertion)
                                .addOnSuccessListener(new AuthResultOnSuccessListener(callbackContext))
                                .addOnFailureListener(new AuthResultOnFailureListener(callbackContext))
                                .addOnCompleteListener(new OnCompleteListener<AuthResult>() {
                                    @Override
                                    public void onComplete(@NonNull Task<AuthResult> task) {
                                        multiFactorResolver = null;
                                    }
                                });
                    } else {
                        // Enrolling second factor
                        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                        if (user != null) {
                            user.getMultiFactor().enroll(multiFactorAssertion, null)
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
                        } else {
                            callbackContext.error("No user is currently signed in");
                        }
                    }
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
                    JSONArray result = new JSONArray();
                    for (MultiFactorInfo factorInfo : enrolledFactors) {
                        JSONObject factor = new JSONObject();
                        factor.put("displayName", factorInfo.getDisplayName());
                        factor.put("factorId", factorInfo.getFactorId());
                        if (factorInfo instanceof PhoneMultiFactorInfo) {
                            factor.put("phoneNumber", ((PhoneMultiFactorInfo) factorInfo).getPhoneNumber());
                        }
                        result.put(factor);
                    }
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
                    result.put("key", key);
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
                    .build();

            GetCredentialRequest request = new GetCredentialRequest.Builder()
                    .addCredentialOption(googleIdOption)
                    .build();

            credentialManager.getCredentialAsync(
                    cordova.getActivity(),
                    request,
                    null,
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
                                        returnResult.put("key", key);
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
                    OAuthProvider.Builder provider = OAuthProvider.newBuilder("apple.com");
                    if (args.length() > 0 && !args.isNull(0)) {
                        String locale = args.getString(0);
                        Map<String, String> customParameters = new HashMap<>();
                        customParameters.put("locale", locale);
                        provider.setCustomParameters(customParameters);
                    }

                    authResultCallbackContext = callbackContext;
                    Task<AuthResult> pending = FirebaseAuth.getInstance().getPendingAuthResult();
                    if (pending != null) {
                        handleAuthTaskOutcome(pending, callbackContext);
                    } else {
                        handleAuthTaskOutcome(
                                FirebaseAuth.getInstance().startActivityForSignInWithProvider(cordova.getActivity(), provider.build()),
                                callbackContext
                        );
                    }
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
                    OAuthProvider.Builder provider = OAuthProvider.newBuilder("microsoft.com");
                    if (args.length() > 0 && !args.isNull(0)) {
                        String locale = args.getString(0);
                        Map<String, String> customParameters = new HashMap<>();
                        customParameters.put("locale", locale);
                        provider.setCustomParameters(customParameters);
                    }

                    authResultCallbackContext = callbackContext;
                    Task<AuthResult> pending = FirebaseAuth.getInstance().getPendingAuthResult();
                    if (pending != null) {
                        handleAuthTaskOutcome(pending, callbackContext);
                    } else {
                        handleAuthTaskOutcome(
                                FirebaseAuth.getInstance().startActivityForSignInWithProvider(cordova.getActivity(), provider.build()),
                                callbackContext
                        );
                    }
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

    private void authenticateUserWithOAuth(final CallbackContext callbackContext, final JSONArray args) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    String providerId = args.getString(0);
                    JSONObject options = args.length() > 1 && !args.isNull(1) ? args.getJSONObject(1) : null;

                    OAuthProvider.Builder provider = OAuthProvider.newBuilder(providerId);

                    if (options != null) {
                        if (options.has("customParameters")) {
                            JSONObject customParams = options.getJSONObject("customParameters");
                            Map<String, String> paramMap = new HashMap<>();
                            java.util.Iterator<String> keys = customParams.keys();
                            while (keys.hasNext()) {
                                String key = keys.next();
                                paramMap.put(key, customParams.getString(key));
                            }
                            provider.setCustomParameters(paramMap);
                        }
                        if (options.has("scopes")) {
                            JSONArray scopes = options.getJSONArray("scopes");
                            java.util.List<String> scopeList = new java.util.ArrayList<>();
                            for (int i = 0; i < scopes.length(); i++) {
                                scopeList.add(scopes.getString(i));
                            }
                            provider.setScopes(scopeList);
                        }
                    }

                    authResultCallbackContext = callbackContext;
                    Task<AuthResult> pending = FirebaseAuth.getInstance().getPendingAuthResult();
                    if (pending != null) {
                        handleAuthTaskOutcome(pending, callbackContext);
                    } else {
                        handleAuthTaskOutcome(
                                FirebaseAuth.getInstance().startActivityForSignInWithProvider(cordova.getActivity(), provider.build()),
                                callbackContext
                        );
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
        user.getIdToken(true).addOnCompleteListener(new OnCompleteListener<GetTokenResult>() {
            @Override
            public void onComplete(@NonNull Task<GetTokenResult> task) {
                try {
                    JSONObject returnResults = new JSONObject();
                    if (task.isSuccessful()) {
                        String idToken = task.getResult().getToken();
                        returnResults.put("idToken", idToken);
                        Map<String, Object> claims = task.getResult().getClaims();
                        returnResults.put("claims", new JSONObject(claims));
                    }
                    returnResults.put("name", user.getDisplayName());
                    returnResults.put("email", user.getEmail());
                    returnResults.put("emailIsVerified", user.isEmailVerified());
                    returnResults.put("phoneNumber", user.getPhoneNumber());
                    returnResults.put("photoUrl", user.getPhotoUrl() != null ? user.getPhotoUrl().toString() : null);
                    returnResults.put("uid", user.getUid());
                    returnResults.put("providerId", user.getProviderId());
                    returnResults.put("isAnonymous", user.isAnonymous());

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

                    callbackContext.success(returnResults);
                } catch (Exception e) {
                    callbackContext.error(e.getMessage());
                }
            }
        });
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

                    if (profile.has("displayName")) {
                        profileBuilder.setDisplayName(profile.getString("displayName"));
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
            String key;
            if (args.get(0) instanceof JSONObject) {
                JSONObject jsonCredential = args.getJSONObject(0);
                key = jsonCredential.getString("key");
            } else {
                key = args.getString(0);
            }

            if (authCredentials.containsKey(key)) {
                return authCredentials.get(key);
            }

            // Try to interpret as verificationId/code pair
            if (args.length() >= 2) {
                String verificationId = key;
                String code = args.getString(1);
                return PhoneAuthProvider.getCredential(verificationId, code);
            }
        } catch (Exception e) {
            Log.e(TAG, "Error obtaining auth credential: " + e.getMessage(), e);
        }
        return null;
    }

    private OAuthProvider obtainAuthProvider(JSONArray args) {
        try {
            String key;
            if (args.get(0) instanceof JSONObject) {
                JSONObject jsonProvider = args.getJSONObject(0);
                key = jsonProvider.getString("key");
            } else {
                key = args.getString(0);
            }

            if (authProviders.containsKey(key)) {
                return authProviders.get(key);
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
        try {
            JSONObject returnResults = new JSONObject();
            FirebaseUser user = authResult.getUser();

            if (user != null) {
                returnResults.put("name", user.getDisplayName());
                returnResults.put("email", user.getEmail());
                returnResults.put("emailIsVerified", user.isEmailVerified());
                returnResults.put("phoneNumber", user.getPhoneNumber());
                returnResults.put("photoUrl", user.getPhotoUrl() != null ? user.getPhotoUrl().toString() : null);
                returnResults.put("uid", user.getUid());
                returnResults.put("providerId", user.getProviderId());
                returnResults.put("isAnonymous", user.isAnonymous());
            }

            AuthCredential credential = authResult.getCredential();
            if (credential != null) {
                String key = saveAuthCredential(credential);
                returnResults.put("key", key);

                if (credential instanceof OAuthCredential) {
                    OAuthCredential oAuthCredential = (OAuthCredential) credential;
                    returnResults.put("idToken", oAuthCredential.getIdToken());
                    returnResults.put("accessToken", oAuthCredential.getAccessToken());
                    returnResults.put("secret", oAuthCredential.getSecret());
                }
            }

            if (authResult.getAdditionalUserInfo() != null) {
                returnResults.put("isNewUser", authResult.getAdditionalUserInfo().isNewUser());
                if (authResult.getAdditionalUserInfo().getProfile() != null) {
                    returnResults.put("profile", new JSONObject(authResult.getAdditionalUserInfo().getProfile()));
                }
            }

            callbackContext.success(returnResults);
        } catch (Exception e) {
            callbackContext.error("Error processing auth result: " + e.getMessage());
        }
    }

    private void handleAuthResultFailure(Exception exception, CallbackContext callbackContext) {
        try {
            if (exception instanceof FirebaseAuthMultiFactorException) {
                FirebaseAuthMultiFactorException multiFactorException = (FirebaseAuthMultiFactorException) exception;
                multiFactorResolver = multiFactorException.getResolver();

                JSONObject errorResult = new JSONObject();
                errorResult.put("code", "auth/multi-factor-auth-required");
                errorResult.put("message", exception.getMessage());

                JSONArray secondFactors = new JSONArray();
                for (MultiFactorInfo info : multiFactorResolver.getHints()) {
                    JSONObject factor = new JSONObject();
                    factor.put("displayName", info.getDisplayName());
                    factor.put("factorId", info.getFactorId());
                    if (info instanceof PhoneMultiFactorInfo) {
                        factor.put("phoneNumber", ((PhoneMultiFactorInfo) info).getPhoneNumber());
                    }
                    secondFactors.put(factor);
                }
                errorResult.put("secondFactors", secondFactors);

                callbackContext.error(errorResult);
            } else {
                String code = "auth/unknown";
                String message = exception.getMessage();
                if (exception instanceof com.google.firebase.auth.FirebaseAuthException) {
                    code = ((com.google.firebase.auth.FirebaseAuthException) exception).getErrorCode();
                }

                JSONObject errorResult = new JSONObject();
                errorResult.put("code", code);
                errorResult.put("message", message);

                // Check for credential-already-in-use
                if (exception instanceof com.google.firebase.auth.FirebaseAuthUserCollisionException) {
                    com.google.firebase.auth.FirebaseAuthUserCollisionException collisionException =
                            (com.google.firebase.auth.FirebaseAuthUserCollisionException) exception;
                    AuthCredential updatedCredential = collisionException.getUpdatedCredential();
                    if (updatedCredential != null) {
                        String key = saveAuthCredential(updatedCredential);
                        errorResult.put("key", key);
                    }
                }

                callbackContext.error(errorResult);
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

        AuthResultOnSuccessListener(CallbackContext callbackContext) {
            this.callbackContext = callbackContext;
        }

        @Override
        public void onSuccess(AuthResult authResult) {
            handleAuthResultSuccess(authResult, callbackContext);
        }
    }

    private class AuthResultOnFailureListener implements OnFailureListener {
        private CallbackContext callbackContext;

        AuthResultOnFailureListener(CallbackContext callbackContext) {
            this.callbackContext = callbackContext;
        }

        @Override
        public void onFailure(@NonNull Exception e) {
            handleAuthResultFailure(e, callbackContext);
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
