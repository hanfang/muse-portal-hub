// Android module. Requires the Android SDK to compile; the :protocol module
// (pure JVM Kotlin) carries all protocol logic and its unit tests.
plugins {
    id("com.android.application") version "8.5.2"
    kotlin("android") version "2.0.21"
}

android {
    namespace = "com.muse.gadget.portal"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.muse.gadget.portal"
        minSdk = 28 // Meta Portal (Android 9+)
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":protocol"))

    // Edge-TTS transport (OkHttp WebSocket) + openWakeWord (ONNX Runtime).
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.github.msnilsen:openwakeword-android:0.1.0")

    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.4")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:1.11.4")
}
