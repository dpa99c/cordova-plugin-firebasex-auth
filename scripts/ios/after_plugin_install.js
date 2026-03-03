/**
 * @file after_plugin_install.js
 * @brief Hook script that runs after the auth plugin is installed on iOS.
 *
 * Configures authentication-related settings in the iOS platform based on plugin variables:
 *
 * - `SETUP_RECAPTCHA_VERIFICATION`: When `true`, reads the `REVERSED_CLIENT_ID` from
 *   `GoogleService-Info.plist` and adds it as a URL scheme in the app's `Info.plist`.
 *   Required for Firebase phone authentication with reCAPTCHA verification.
 *
 * - `IOS_ENABLE_APPLE_SIGNIN`: When `true`, adds the `com.apple.developer.applesignin`
 *   entitlement with `["Default"]` to both Debug and Release entitlements plists.
 *
 * - `IOS_GOOGLE_SIGIN_VERSION`: When set, overrides the GoogleSignIn pod version in the
 *   Podfile to the specified semantic version.
 *
 * Plugin variables are resolved using a 4-layer override strategy:
 * 1. Defaults from plugin.xml preferences (via hook context).
 * 2. Overrides from `config.xml` `<plugin><variable>` elements (wrapper and own plugin ID).
 * 3. Overrides from `package.json` `cordova.plugins` entries (wrapper and own plugin ID).
 * 4. CLI variables passed at install time (highest priority).
 */
var fs = require("fs");
var path = require("path");
var plist = require("plist");

/** @constant {string} The plugin identifier. */
var PLUGIN_ID = "cordova-plugin-firebasex-auth";
/** @constant {string} The wrapper meta-plugin identifier used as a fallback source for plugin variables. */
var WRAPPER_PLUGIN_ID = "cordova-plugin-firebasex";

/**
 * Cordova hook entry point.
 *
 * Resolves plugin variables from the context, determines the app name from `config.xml`,
 * then applies authentication configuration based on enabled plugin variables.
 *
 * @param {object} context - The Cordova hook context.
 */
module.exports = function(context) {
    /**
     * @type {Object} Resolved plugin variable key/value pairs.
     * Defaults are extracted from plugin.xml preferences, then overridden by CLI variables.
     */
    var pluginVariables = {};
    // Extract default plugin variable values from plugin.xml preference elements
    var plugin = context.opts.plugin;
    if(plugin && plugin.pluginInfo && plugin.pluginInfo._et && plugin.pluginInfo._et._root && plugin.pluginInfo._et._root._children){
        plugin.pluginInfo._et._root._children.forEach(function(child){
            if(child.tag === "preference"){
                pluginVariables[child.attrib.name] = child.attrib.default;
            }
        });
    }

    // Override with values from config.xml (check both wrapper and own plugin ID)
    try {
        var configXmlPath = path.join(context.opts.projectRoot, "config.xml");
        if (fs.existsSync(configXmlPath)) {
            var configXml = fs.readFileSync(configXmlPath, "utf-8");
            [WRAPPER_PLUGIN_ID, PLUGIN_ID].forEach(function(pluginId) {
                var pluginRegex = new RegExp('<plugin[^>]+name="' + pluginId + '"[^>]*>(.*?)</plugin>', "s");
                var pluginMatch = configXml.match(pluginRegex);
                if (pluginMatch) {
                    var varRegex = /<variable\s+name="([^"]+)"\s+value="([^"]+)"\s*\/>/g;
                    var varMatch;
                    while ((varMatch = varRegex.exec(pluginMatch[1])) !== null) {
                        pluginVariables[varMatch[1]] = varMatch[2];
                    }
                }
            });
        }
    } catch (e) {
        console.warn("[FirebasexAuth] Could not read config.xml for plugin variables: " + e.message);
    }

    // Override with values from package.json (check wrapper first as base, then own plugin)
    try {
        var packageJsonPath = path.join(context.opts.projectRoot, "package.json");
        if (fs.existsSync(packageJsonPath)) {
            var packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
            if (packageJson.cordova && packageJson.cordova.plugins) {
                [WRAPPER_PLUGIN_ID, PLUGIN_ID].forEach(function(pluginId) {
                    if (packageJson.cordova.plugins[pluginId]) {
                        var pluginVars = packageJson.cordova.plugins[pluginId];
                        for (var key in pluginVars) {
                            pluginVariables[key] = pluginVars[key];
                        }
                    }
                });
            }
        }
    } catch (e) {
        console.warn("[FirebasexAuth] Could not read package.json for plugin variables: " + e.message);
    }

    // Override with any user-specified CLI variable values (highest priority)
    if(context.opts && context.opts.cli_variables){
        Object.keys(context.opts.cli_variables).forEach(function(key){
            pluginVariables[key] = context.opts.cli_variables[key];
        });
    }

    var iosPlatformPath = path.join(context.opts.projectRoot, "platforms", "ios");
    var appName;
    try {
        var configXmlPath = path.join(context.opts.projectRoot, "config.xml");
        var configXml = fs.readFileSync(configXmlPath, "utf-8");
        var nameMatch = configXml.match(/<name>([^<]+)<\/name>/);
        appName = nameMatch ? nameMatch[1] : null;
    } catch(e) {
        console.warn("[FirebasexAuth] Could not read config.xml to get app name");
        return;
    }

    if (!appName) {
        console.warn("[FirebasexAuth] Could not determine app name from config.xml");
        return;
    }

    // Handle SETUP_RECAPTCHA_VERIFICATION:
    // Adds the REVERSED_CLIENT_ID from GoogleService-Info.plist as a URL scheme
    // in the app's Info.plist, enabling reCAPTCHA-based phone authentication.
    if (pluginVariables["SETUP_RECAPTCHA_VERIFICATION"] === "true") {
        try {
            var googlePlistPath = path.join(iosPlatformPath, appName, "GoogleService-Info.plist");
            if (fs.existsSync(googlePlistPath)) {
                var googlePlist = plist.parse(fs.readFileSync(googlePlistPath, "utf-8"));
                var reversedClientId = googlePlist["REVERSED_CLIENT_ID"];
                if (reversedClientId) {
                    var appPlistPath = path.join(iosPlatformPath, appName, appName + "-Info.plist");
                    var appPlist = plist.parse(fs.readFileSync(appPlistPath, "utf-8"));

                    if (!appPlist["CFBundleURLTypes"]) appPlist["CFBundleURLTypes"] = [];
                    var alreadyExists = false;
                    for (var i = 0; i < appPlist["CFBundleURLTypes"].length; i++) {
                        var entry = appPlist["CFBundleURLTypes"][i];
                        if (entry["CFBundleURLSchemes"]) {
                            for (var j = 0; j < entry["CFBundleURLSchemes"].length; j++) {
                                if (entry["CFBundleURLSchemes"][j] === reversedClientId) {
                                    alreadyExists = true;
                                    break;
                                }
                            }
                        }
                        if (alreadyExists) break;
                    }
                    if (!alreadyExists) {
                        appPlist["CFBundleURLTypes"].push({
                            CFBundleTypeRole: "Editor",
                            CFBundleURLSchemes: [reversedClientId]
                        });
                        fs.writeFileSync(appPlistPath, plist.build(appPlist));
                        console.log("[FirebasexAuth] Added reversed client ID URL scheme for reCAPTCHA verification");
                    }
                }
            }
        } catch(e) {
            console.warn("[FirebasexAuth] Error setting up reCAPTCHA URL scheme: " + e.message);
        }
    }

    // Handle IOS_ENABLE_APPLE_SIGNIN:
    // Adds the Apple Sign-In entitlement to both Debug and Release entitlements plists,
    // enabling the "Sign in with Apple" capability in the Xcode project.
    if (pluginVariables["IOS_ENABLE_APPLE_SIGNIN"] === "true") {
        try {
            var entitlementsDebugPath = path.join(iosPlatformPath, appName, "Entitlements-Debug.plist");
            var entitlementsReleasePath = path.join(iosPlatformPath, appName, "Entitlements-Release.plist");

            [entitlementsDebugPath, entitlementsReleasePath].forEach(function(entPath) {
                var entPlist = {};
                if (fs.existsSync(entPath)) {
                    entPlist = plist.parse(fs.readFileSync(entPath, "utf-8"));
                }
                entPlist["com.apple.developer.applesignin"] = ["Default"];
                fs.writeFileSync(entPath, plist.build(entPlist));
            });
            console.log("[FirebasexAuth] Added Apple Sign-In entitlement");
        } catch(e) {
            console.warn("[FirebasexAuth] Error setting up Apple Sign-In entitlement: " + e.message);
        }
    }

    // Handle IOS_GOOGLE_SIGIN_VERSION:
    // Overrides the GoogleSignIn pod version in the Podfile to the version
    // specified by the plugin variable, allowing users to pin a specific version.
    if (pluginVariables["IOS_GOOGLE_SIGIN_VERSION"]) {
        try {
            var podFilePath = path.join(iosPlatformPath, "Podfile");
            if (fs.existsSync(podFilePath)) {
                var podFileContents = fs.readFileSync(podFilePath, "utf-8");
                var versionRegex = /\d+\.\d+\.\d+[^'"]*/;
                var googleSignInPodRegEx = /pod 'GoogleSignIn', '(\d+\.\d+\.\d+[^'"]*)'/g;
                var matches = podFileContents.match(googleSignInPodRegEx);
                if (matches) {
                    var modified = false;
                    matches.forEach(function(match) {
                        var currentVersion = match.match(versionRegex)[0];
                        if (currentVersion !== pluginVariables["IOS_GOOGLE_SIGIN_VERSION"]) {
                            podFileContents = podFileContents.replace(match, match.replace(currentVersion, pluginVariables["IOS_GOOGLE_SIGIN_VERSION"]));
                            modified = true;
                        }
                    });
                    if (modified) {
                        fs.writeFileSync(podFilePath, podFileContents);
                        console.log("[FirebasexAuth] Google Sign In version set to v" + pluginVariables["IOS_GOOGLE_SIGIN_VERSION"] + " in Podfile");
                    }
                }
            }
        } catch(e) {
            console.warn("[FirebasexAuth] Error setting Google Sign-In version: " + e.message);
        }
    }
};
