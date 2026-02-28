interface UserProvider {
    providerId: string;
    uid: string;
    displayName?: string;
    email?: string;
    phoneNumber?: string;
    photoUrl?: string;
}

interface FirebaseUser {
    uid: string;
    displayName?: string;
    email?: string;
    emailIsVerified: boolean;
    phoneNumber?: string;
    photoUrl?: string;
    providerId: string;
    providers?: UserProvider[];
}

interface AuthCredential {
    key: string;
    [key: string]: any;
}

interface AuthErrorResult {
    code: string;
    message: string;
    credential?: AuthCredential;
    secondFactors?: Array<{
        displayName?: string;
        phoneNumber?: string;
        factorId: string;
    }>;
}

interface ActionCodeSettings {
    url: string;
    handleCodeInApp?: boolean;
    iOS?: { bundleId: string };
    android?: { packageName: string; installApp?: boolean; minimumVersion?: string };
    dynamicLinkDomain?: string;
}

interface FirebasexAuthPlugin {
    // Phone / MFA
    verifyPhoneNumber(
        success: (result: { verificationId: string; code?: string; instantVerification?: boolean }) => void,
        error: (err: any) => void,
        phoneNumber: string,
        timeOutDuration?: number,
        fakeVerificationCode?: string,
        requireSmsValidation?: boolean
    ): void;

    enrollSecondAuthFactor(
        success: () => void,
        error: (err: any) => void,
        phoneNumber: string,
        displayName: string
    ): void;

    verifySecondAuthFactor(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        verificationId: string,
        code: string
    ): void;

    listEnrolledSecondAuthFactors(
        success: (factors: Array<{ displayName?: string; phoneNumber?: string; factorId: string }>) => void,
        error: (err: any) => void
    ): void;

    unenrollSecondAuthFactor(
        success: () => void,
        error: (err: any) => void,
        selectedIndex: number
    ): void;

    // Language
    setLanguageCode(
        success: () => void,
        error: (err: any) => void,
        lang: string
    ): void;

    // Email/Password
    createUserWithEmailAndPassword(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        email: string,
        password: string
    ): void;

    signInUserWithEmailAndPassword(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        email: string,
        password: string
    ): void;

    authenticateUserWithEmailAndPassword(
        success: (result: { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        email: string,
        password: string
    ): void;

    // Custom token & anonymous
    signInUserWithCustomToken(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        customToken: string
    ): void;

    signInUserAnonymously(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void
    ): void;

    // OAuth Providers
    authenticateUserWithGoogle(
        success: (result: FirebaseUser | { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        clientId: string,
        options?: { signIn?: boolean }
    ): void;

    authenticateUserWithApple(
        success: (result: FirebaseUser | { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        locale?: string
    ): void;

    authenticateUserWithMicrosoft(
        success: (result: FirebaseUser | { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        locale?: string
    ): void;

    authenticateUserWithFacebook(
        success: (result: FirebaseUser | { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        accessToken: string
    ): void;

    authenticateUserWithOAuth(
        success: (result: FirebaseUser | { credential: AuthCredential }) => void,
        error: (err: AuthErrorResult) => void,
        providerId: string,
        options?: { customParameters?: Record<string, string>; scopes?: string[] }
    ): void;

    // Credential operations
    signInWithCredential(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        credential: AuthCredential
    ): void;

    linkUserWithCredential(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        credential: AuthCredential
    ): void;

    reauthenticateWithCredential(
        success: (user: FirebaseUser) => void,
        error: (err: AuthErrorResult) => void,
        credential: AuthCredential
    ): void;

    unlinkUserWithProvider(
        success: () => void,
        error: (err: any) => void,
        providerId: string
    ): void;

    // Session
    isUserSignedIn(
        success: (signedIn: boolean) => void,
        error: (err: any) => void
    ): void;

    signOutUser(
        success: () => void,
        error: (err: any) => void
    ): void;

    getCurrentUser(
        success: (user: FirebaseUser) => void,
        error: (err: any) => void
    ): void;

    reloadCurrentUser(
        success: (user: FirebaseUser) => void,
        error: (err: any) => void
    ): void;

    // User management
    updateUserProfile(
        success: () => void,
        error: (err: any) => void,
        profile: { displayName?: string; photoUri?: string }
    ): void;

    updateUserEmail(
        success: () => void,
        error: (err: any) => void,
        email: string
    ): void;

    sendUserEmailVerification(
        success: () => void,
        error: (err: any) => void,
        actionCodeSettings?: ActionCodeSettings
    ): void;

    verifyBeforeUpdateEmail(
        success: () => void,
        error: (err: any) => void,
        email: string,
        actionCodeSettings?: ActionCodeSettings
    ): void;

    updateUserPassword(
        success: () => void,
        error: (err: any) => void,
        password: string
    ): void;

    sendUserPasswordResetEmail(
        success: () => void,
        error: (err: any) => void,
        email: string
    ): void;

    deleteUser(
        success: () => void,
        error: (err: any) => void
    ): void;

    // Auth state listeners
    registerAuthStateChangeListener(fn: (userSignedIn: boolean) => void): void;
    registerAuthIdTokenChangeListener(fn: (userSignedIn: boolean) => void): void;

    // Config
    useAuthEmulator(
        success: () => void,
        error: (err: any) => void,
        host: string,
        port: number
    ): void;

    getClaims(
        success: (claims: Record<string, any>) => void,
        error: (err: any) => void
    ): void;
}
