// SPDX-License-Identifier: Apache-2.0
//
// io.github.qorechain:qoresign - QoreSign for Kotlin on the JVM.
// UniFFI bindings over the Rust core (crates/qoresign-ffi), loaded with JNA.
// Native libraries are JNA resources (<os>-<arch>/), built into ./natives by
// scripts/build-kotlin-natives.sh.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

buildscript {
    // The Android Gradle Plugin shares this class loader with the Kotlin
    // plugin; it is resolved only when the Android module is enabled.
    if (providers.gradleProperty("qoresignAndroid").orNull == "true") {
        repositories {
            google()
            mavenCentral()
        }
        dependencies {
            classpath("com.android.tools.build:gradle:9.4.1")
        }
    }
}

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.4.21"
    id("com.vanniktech.maven.publish") version "0.37.0"
}

group = "io.github.qorechain"
version = "0.1.0"

val jnaVersion = "5.19.1"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjdk-release=17")
    }
}

sourceSets {
    main {
        resources.srcDir("natives")
    }
}

dependencies {
    api("net.java.dev.jna:jna:$jnaVersion")

    testImplementation(platform("org.junit:junit-bom:5.14.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

tasks.test {
    useJUnitPlatform()
    systemProperty("qoresign.vectors", file("../vectors/qoresign-v1.json").absolutePath)
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.jar {
    manifest {
        attributes("Automatic-Module-Name" to "io.github.qorechain.qoresign")
    }
}

mavenPublishing {
    // Central Portal. Publishing runs only from the release workflow
    // (`./gradlew publishToMavenCentral`; the deployment is then released in
    // the Central Portal), with credentials passed as ORG_GRADLE_PROJECT_*
    // environment variables. Nothing is committed.
    publishToMavenCentral(automaticRelease = false)
    // Sign only when a key is configured, so publishToMavenLocal works without one.
    if (project.hasProperty("signingInMemoryKey") || project.hasProperty("signing.keyId")) {
        signAllPublications()
    }

    coordinates("io.github.qorechain", "qoresign", version.toString())

    pom {
        name.set("QoreSign")
        description.set(
            "Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing, verification and " +
                "Sign In With QoreChain for Kotlin on the JVM."
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
