// SPDX-License-Identifier: Apache-2.0
//
// io.github.qorechain:qoresign-android - the same bindings as the JVM artifact
// (../src/main/kotlin) packaged as an AAR with jniLibs for arm64-v8a,
// armeabi-v7a and x86_64, built by
// `scripts/build-kotlin-natives.sh android` (needs ANDROID_NDK_HOME).
// Enabled with -PqoresignAndroid=true; needs an Android SDK (ANDROID_HOME).

plugins {
    id("com.android.library")
    id("com.vanniktech.maven.publish")
}

group = "io.github.qorechain"
version = "0.1.1"

val jnaVersion = "5.19.1"

android {
    namespace = "io.github.qorechain.qoresign"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDir("../src/main/kotlin")
        }
    }
}

dependencies {
    api("net.java.dev.jna:jna:$jnaVersion@aar")
}

mavenPublishing {
    publishToMavenCentral(automaticRelease = false)
    if (project.hasProperty("signingInMemoryKey") || project.hasProperty("signing.keyId")) {
        signAllPublications()
    }

    coordinates("io.github.qorechain", "qoresign-android", version.toString())

    pom {
        name.set("QoreSign for Android")
        description.set(
            "Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and " +
                "Sign In With QoreChain for Android."
        )
        url.set("https://github.com/qorechain/qoresign")
        licenses {
            license {
                name.set("Apache License 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
            }
        }
        developers {
            developer {
                id.set("qorechain")
                name.set("QoreChain Association")
                url.set("https://github.com/qorechain")
            }
        }
        scm {
            url.set("https://github.com/qorechain/qoresign")
            connection.set("scm:git:https://github.com/qorechain/qoresign.git")
            developerConnection.set("scm:git:ssh://git@github.com/qorechain/qoresign.git")
        }
    }
}
