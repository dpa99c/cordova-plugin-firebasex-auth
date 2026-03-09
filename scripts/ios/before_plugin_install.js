/**
 * @file before_plugin_install.js
 * @brief Hook script that runs before the auth plugin is installed on iOS.
 *
 * Deletes the Podfile.lock (if present) to ensure CocoaPods performs a fresh
 * dependency resolution when this plugin installs. This is necessary because:
 *
 * - GoogleSignIn 9.0.0 requires `GTMSessionFetcher/Core ~> 3.3` (i.e., >= 3.3 and < 4.0)
 * - Other Firebase plugins (e.g. FirebaseFunctions) may have previously triggered a
 *   pod install that locked GTMSessionFetcher to 5.1.0 (satisfying their wider
 *   `>= 3.4, < 6.0` constraint, but incompatible with GoogleSignIn's ~> 3.3)
 * - An existing Podfile.lock that pins GTMSessionFetcher to 5.1.0 causes the next
 *   pod install (which adds GoogleSignIn) to fail with a deployment target conflict
 *
 * By deleting the lock before this plugin is installed, CocoaPods performs a fresh
 * resolution and selects GTMSessionFetcher 3.5.0 -- which satisfies both Firebase's
 * `>= 3.4, < 6.0` and GoogleSignIn's `~> 3.3` requirements.
 */
var fs = require("fs");
var path = require("path");

module.exports = function(context) {
    var podfileLockPath = path.join(context.opts.projectRoot, "platforms", "ios", "Podfile.lock");
    if (fs.existsSync(podfileLockPath)) {
        fs.unlinkSync(podfileLockPath);
        console.log("[FirebasexAuth] Deleted Podfile.lock to allow fresh CocoaPods resolution (GTMSessionFetcher version compatibility with GoogleSignIn)");
    }
};
