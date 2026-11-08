import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Release signing. The keystore is never in the repository: its location and
// passwords come from environment variables (CI) or from an untracked
// android/keystore.properties (local builds). Without them, the release APK is
// left unsigned. See docs/RELEASING.md.
val keystoreProps = Properties().apply {
    val f = rootProject.file("keystore.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun signingValue(env: String, prop: String): String? =
    System.getenv(env)?.takeIf { it.isNotEmpty() } ?: keystoreProps.getProperty(prop)

val releaseStoreFile = signingValue("BEACON_KEYSTORE", "storeFile")

android {
    namespace = "org.beacon.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "org.beacon.app"
        minSdk = 26 // matches gomobile bind -androidapi 26
        targetSdk = 36
        // Set by the release workflow from the tag: -PversionName=1.0.0 -PversionCode=10000.
        versionCode = (findProperty("versionCode") as String?)?.toInt() ?: 10000
        versionName = (findProperty("versionName") as String?) ?: "1.0.0"
    }

    signingConfigs {
        if (releaseStoreFile != null) {
            create("release") {
                storeFile = file(releaseStoreFile)
                storePassword = signingValue("BEACON_KEYSTORE_PASSWORD", "storePassword")
                keyAlias = signingValue("BEACON_KEY_ALIAS", "keyAlias")
                keyPassword = signingValue("BEACON_KEY_PASSWORD", "keyPassword")
                enableV1Signing = false // minSdk 26 uses APK Signature Scheme v2+
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    // The Go core, built by ../scripts/build-aar.sh.
    implementation(files("libs/core.aar"))

    implementation(platform("androidx.compose:compose-bom:2026.06.01"))
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517") // real org.json on the JVM; Android's is a stub there
}
