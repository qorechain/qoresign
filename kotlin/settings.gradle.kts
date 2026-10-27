// SPDX-License-Identifier: Apache-2.0

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
    }
}

rootProject.name = "qoresign"

// The Android library builds only when asked for (-PqoresignAndroid=true), so
// the JVM build and tests need no Android SDK.
if (providers.gradleProperty("qoresignAndroid").orNull == "true") {
    include(":android")
}
