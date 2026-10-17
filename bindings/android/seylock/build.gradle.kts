// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//
// The SeyLock Android library: a Kotlin API over the C ABI, through JNA (the
// mechanism UniFFI's Kotlin bindings use), with libseylock.so for
// arm64-v8a, armeabi-v7a and x86_64. tools/build_android_libs.sh builds the
// native libraries into src/main/jniLibs.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

group = "io.github.arkhanhel"
version = "0.2.0"

android {
    namespace = "io.github.arkhanhel.seylock"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // The device test runs as a current application would, so the platform's
    // ban on plain HTTP applies and the shipped configuration is what lifts it.
    testOptions {
        targetSdk = 35
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

// Maven coordinates io.github.arkhanhel:seylock. `publishToMavenLocal` checks
// the artifact; publishing to Maven Central needs the owner's Central Portal
// account and signing key, configured outside this repository.
publishing {
    publications {
        register<MavenPublication>("release") {
            artifactId = "seylock"
            afterEvaluate { from(components["release"]) }
            pom {
                name.set("SeyLock")
                description.set(
                    "Reach your own servers from networks that block them: signed lists of " +
                        "ways in, paths that race, a local reverse proxy.",
                )
                url.set("https://github.com/Arkhanhel/seylock")
                licenses {
                    license {
                        name.set("Mozilla Public License 2.0")
                        url.set("https://www.mozilla.org/en-US/MPL/2.0/")
                    }
                }
                developers {
                    developer {
                        id.set("Arkhanhel")
                        name.set("Yurii Arkhanhelskyi")
                    }
                }
                scm {
                    url.set("https://github.com/Arkhanhel/seylock")
                    connection.set("scm:git:https://github.com/Arkhanhel/seylock.git")
                }
            }
        }
    }
}

dependencies {
    // Android needs the AAR, which carries JNA's own native library.
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    // Unit tests run on the build machine's JVM, with the desktop JAR and the
    // host build of the library (target/release).
    testImplementation("net.java.dev.jna:jna:5.17.0")
    testImplementation("junit:junit:4.13.2")
    // On-device tests: the AAR's own libseylock.so, loaded by JNA on Android.
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

tasks.withType<Test>().configureEach {
    systemProperty(
        "jna.library.path",
        rootProject.projectDir.resolve("../../target/release").absolutePath,
    )
    systemProperty(
        "seylock.vectors",
        rootProject.projectDir.resolve("../../test-vectors/endpoints.json").absolutePath,
    )
}
