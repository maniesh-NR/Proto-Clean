plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.protoclean"
    compileSdk = 34

    defaultConfig {
        applicationId = "app.protoclean"
        minSdk = 26            // Android 8.0 Oreo
        targetSdk = 34
        versionCode = 8
        versionName = "0.6.2"
    }

    // Per-ABI APKs (armv7 + arm64) as requested for the release matrix.
    splits {
        abi {
            isEnable = true
            reset()
            include("armeabi-v7a", "arm64-v8a")
            isUniversalApk = false
        }
    }

    // Release signing: CI decodes the release keystore (GitHub Actions
    // secrets PROTO_ANDROID_KEYSTORE_*) and points PC_KEYSTORE_FILE at
    // it. A release-signed, non-debuggable APK is what Google Play
    // Protect expects from a sideloaded app — debug-signed APKs get the
    // scary "unsafe app" biometric confirmation. When the keystore is
    // absent (local builds, forks without the secrets) we fall back to
    // the debug key so assembleRelease still produces installable APKs.
    val keystoreFile = providers.environmentVariable("PC_KEYSTORE_FILE").orNull
    val keystorePassword = providers.environmentVariable("PC_KEYSTORE_PASSWORD").orNull
    val keyAlias = providers.environmentVariable("PC_KEY_ALIAS").orNull
    val keyPassword = providers.environmentVariable("PC_KEY_PASSWORD").orNull
    val releaseKeystore = keystoreFile?.let { file(it) }?.takeIf { it.exists() }

    signingConfigs {
        if (releaseKeystore != null && keystorePassword != null && keyAlias != null &&
            keyPassword != null
        ) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = keystorePassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val releaseSigning = signingConfigs.findByName("release")
            if (releaseSigning != null) {
                signingConfig = releaseSigning
            } else {
                // No release keystore available — sign with the debug key
                // so the artifact is at least installable (CI logs make
                // this visible).
                logger.warn(
                    "PC_KEYSTORE_FILE not set or missing: release APK " +
                        "will be DEBUG-signed (fine for local builds, " +
                        "not for distribution)")
                signingConfig = signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true   // required by the WG tunnel lib
    }
    kotlinOptions { jvmTarget = "17" }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.14" }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    // WireGuard userspace backend (wireguard-go + VpnService plumbing)
    // NOTE: tunnel is published on Maven Central with calendar versions;
    // 1.2.1 does not exist. Desugaring is required by the library.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.3")
    implementation("com.wireguard.android:tunnel:1.0.20260102")

    // UI
    val composeBom = platform("androidx.compose:compose-bom:2024.06.00")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.9.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.navigation:navigation-compose:2.7.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.2")

    // data
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    debugImplementation("androidx.compose.ui:ui-tooling")

    // unit tests (ImportParser + GuestApi + friends)
    testImplementation("junit:junit:4.13.2")
    // GuestApiTest uses OkHttp's Interceptor/StubApi (already in
    // `implementation`, re-declared here so the test classpath is
    // explicit even if the Android Gradle Plugin changes its
    // implementation->test classpath bridging).
    testImplementation("com.squareup.okhttp3:okhttp:4.12.0")
    // org.json is bundled in the Android SDK but its stub throws
    // "not mocked" in JVM unit tests — pull in the real artifact so
    // GuestApi / GuestApiTest can parse JSON on the JVM.
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1")
}
