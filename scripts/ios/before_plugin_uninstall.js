/**
 * @file before_plugin_uninstall.js
 * @brief Hook script that runs before the auth plugin is uninstalled from iOS.
 *
 * No explicit cleanup is required; Cordova's built-in plugin removal process
 * handles reverting changes made during installation.
 */
module.exports = function(context) {
    // Cleanup is handled by Cordova's plugin removal process
    console.log("[FirebasexAuth] Plugin uninstalled");
};
