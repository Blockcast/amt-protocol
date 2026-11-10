import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// AGP and Kotlin come from the root project's plugins block.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.blockcast.amt.sample"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.blockcast.amt.sample"
        minSdk = 29 // Driad.resolveRelay uses DnsResolver.rawQuery
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        release {
            // Test APK only: sign with the debug key so `assembleRelease` output installs.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":"))
}
