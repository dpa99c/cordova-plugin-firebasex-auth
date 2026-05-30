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

var PLUGIN_ID = "cordova-plugin-firebasex-auth";
var WRAPPER_PLUGIN_ID = "cordova-plugin-firebasex";

function isSwiftPackageManagerEnabled(projectRoot) {
    var iosPlatformPath = path.join(projectRoot, "platforms", "ios");
    var appSubDirPath = path.join(iosPlatformPath, "App");
    return fs.existsSync(appSubDirPath) && fs.statSync(appSubDirPath).isDirectory();
}

function resolvePluginVariables(context) {
    var pluginVariables = {};
    var plugin = context.opts.plugin;

    if (plugin && plugin.pluginInfo && plugin.pluginInfo._et && plugin.pluginInfo._et._root && plugin.pluginInfo._et._root._children) {
        plugin.pluginInfo._et._root._children.forEach(function(child) {
            if (child.tag === "preference") {
                pluginVariables[child.attrib.name] = child.attrib.default;
            }
        });
    }

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

    if (context.opts && context.opts.cli_variables) {
        Object.keys(context.opts.cli_variables).forEach(function(key) {
            pluginVariables[key] = context.opts.cli_variables[key];
        });
    }

    return pluginVariables;
}

function rewritePackageSwiftValue(packageSwiftContents, key, value) {
    var packageValueRegex = new RegExp("let " + key + "(?:\\s*:\\s*Version)? = \\\"[^\\\"]+\\\"");
    if (!packageValueRegex.test(packageSwiftContents)) {
        return { contents: packageSwiftContents, modified: false };
    }

    var updatedContents = packageSwiftContents.replace(packageValueRegex, function(match) {
        return match.replace(/\"[^\"]+\"/, '"' + value + '"');
    });

    return { contents: updatedContents, modified: updatedContents !== packageSwiftContents };
}

module.exports = function(context) {
    var pluginVariables = resolvePluginVariables(context);
    if (isSwiftPackageManagerEnabled(context.opts.projectRoot)) {
        var packageSwiftPaths = [
            path.resolve(__dirname, "..", "..", "Package.swift"),
            path.join(context.opts.projectRoot, "plugins", PLUGIN_ID, "Package.swift")
        ].filter(function(packageSwiftPath, index, paths) {
            return fs.existsSync(packageSwiftPath) && paths.indexOf(packageSwiftPath) === index;
        });

        packageSwiftPaths.forEach(function(packageSwiftPath) {
            var packageSwiftContents = fs.readFileSync(packageSwiftPath, "utf-8");
            var modified = false;

            [["firebaseSDKVersion", pluginVariables["IOS_FIREBASE_SDK_VERSION"]], ["googleSignInVersion", pluginVariables["IOS_GOOGLE_SIGIN_VERSION"]]].forEach(function(update) {
                if (!update[1]) return;
                var result = rewritePackageSwiftValue(packageSwiftContents, update[0], update[1]);
                packageSwiftContents = result.contents;
                modified = modified || result.modified;
            });

            if (modified) {
                fs.writeFileSync(packageSwiftPath, packageSwiftContents);
            }
        });

        return;
    }

    var podfileLockPath = path.join(context.opts.projectRoot, "platforms", "ios", "Podfile.lock");
    if (fs.existsSync(podfileLockPath)) {
        fs.unlinkSync(podfileLockPath);
        console.log("[FirebasexAuth] Deleted Podfile.lock to allow fresh CocoaPods fallback resolution");
    }
};
