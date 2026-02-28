var fs = require("fs");
var path = require("path");
var plist = require("plist");

module.exports = function(context) {
    var pluginVariables = {};
    var plugin = context.opts.plugin;
    if(plugin && plugin.pluginInfo && plugin.pluginInfo._et && plugin.pluginInfo._et._root && plugin.pluginInfo._et._root._children){
        plugin.pluginInfo._et._root._children.forEach(function(child){
            if(child.tag === "preference"){
                pluginVariables[child.attrib.name] = child.attrib.default;
            }
        });
    }

    // Override with any user-specified variable values
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

    // Handle SETUP_RECAPTCHA_VERIFICATION
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

    // Handle IOS_ENABLE_APPLE_SIGNIN
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

    // Handle IOS_GOOGLE_SIGIN_VERSION in Podfile
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
