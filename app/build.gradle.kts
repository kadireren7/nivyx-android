import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ktlint)
}

val nivyxVersion: String = providers.gradleProperty("nivyx.version").get()
val nivyxAbis: List<String> = providers.gradleProperty("nivyx.abis").get().split(",").map { it.trim() }.filter { it.isNotEmpty() }
val versionParts = nivyxVersion.substringBefore('-').split('.').map { it.toInt() }
val ndkVersionPinned = "27.2.12479018"

// Signing material comes from the environment only; nothing secret is ever committed.
val signingFile: String? = System.getenv("NIVYX_KEYSTORE_FILE")?.takeIf { it.isNotBlank() }
val signingConfigured = signingFile != null &&
    !System.getenv("NIVYX_KEYSTORE_PASSWORD").isNullOrEmpty() &&
    !System.getenv("NIVYX_KEY_ALIAS").isNullOrEmpty()

android {
    namespace = "app.nivyx.android"
    compileSdk = 36
    ndkVersion = ndkVersionPinned

    defaultConfig {
        applicationId = "app.nivyx.android"
        minSdk = 21
        targetSdk = 36
        versionCode = versionParts[0] * 10_000 + versionParts[1] * 100 + versionParts[2]
        versionName = nivyxVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += nivyxAbis }
        buildConfigField("String", "GITHUB_REPO", "\"kadireren7/nivyx-android\"")
    }

    signingConfigs {
        if (signingConfigured) {
            create("release") {
                storeFile = file(signingFile!!)
                storePassword = System.getenv("NIVYX_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("NIVYX_KEY_ALIAS")
                keyPassword = System.getenv("NIVYX_KEY_PASSWORD") ?: System.getenv("NIVYX_KEYSTORE_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Without signing secrets the release APK is produced unsigned (see docs/release.md).
            signingConfig = if (signingConfigured) signingConfigs.getByName("release") else null
        }
        debug {
            versionNameSuffix = "-debug"
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs { useLegacyPackaging = false }
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "DebugProbesKt.bin")
    }

    // Keep build output free of Google-only dependency metadata blobs (smaller, more reproducible).
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        checkReleaseBuilds = true
        baseline = file("lint-baseline.xml")
        // Versions are pinned on purpose (reproducible builds); updates are a reviewed change, not a lint failure.
        disable += setOf("GradleDependency", "AndroidGradlePluginVersion", "NewerVersionAvailable")
        // x86_64 is part of nivyx.abis by default; lint cannot evaluate the property-driven filter.
        disable += "ChromeOsAbiSupport"
        // targetSdk is a deliberate, reviewed choice (36); newer SDK images must not break the build.
        disable += "OldTargetApi"
    }
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.core.splashscreen)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)

    testImplementation(libs.junit)
    testImplementation(libs.org.json)
    testImplementation(libs.kotlinx.coroutines.test)

    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.rules)
    androidTestImplementation(libs.androidx.test.espresso.core)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}

// ---------------------------------------------------------------------------------------------
// Native (Rust) build integration
// ---------------------------------------------------------------------------------------------

val jniLibsDir = layout.projectDirectory.dir("src/main/jniLibs")
val rustInputs = fileTree(rootDir) {
    include("crates/**/*.rs", "crates/**/Cargo.toml", "crates/**/build.rs", "Cargo.toml", "Cargo.lock", ".cargo/config.toml")
}

val buildRustAndroid by tasks.registering(Exec::class) {
    group = "build"
    description = "Cross-compiles libnivyx_jni.so for every configured ABI with cargo-ndk."
    workingDir = rootDir
    val targets = nivyxAbis.flatMap { listOf("-t", it) }
    environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
    commandLine(listOf("cargo", "ndk") + targets + listOf("-o", jniLibsDir.asFile.absolutePath, "build", "--release", "-p", "nivyx-jni", "--locked"))
    inputs.files(rustInputs)
    inputs.property("abis", nivyxAbis.joinToString(","))
    outputs.dir(jniLibsDir)
}

tasks.matching { it.name.matches(Regex("merge.*JniLibFolders")) }.configureEach { dependsOn(buildRustAndroid) }

val buildRustHost by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds the host-native JNI library so JVM unit tests exercise the real Rust code."
    workingDir = rootDir
    commandLine("cargo", "build", "-p", "nivyx-jni", "--locked")
    inputs.files(rustInputs)
    outputs.file(rootDir.resolve("target/debug/libnivyx_jni.so"))
}

tasks.withType<Test>().configureEach {
    dependsOn(buildRustHost)
    systemProperty("java.library.path", rootDir.resolve("target/debug").absolutePath)
}
