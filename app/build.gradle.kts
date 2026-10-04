// Root build: shared repository configuration only.
allprojects {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        maven { url = uri("https://jitpack.io") } // openwakeword-android
    }
}
