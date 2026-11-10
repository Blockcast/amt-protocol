import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library") version "8.13.2"
    id("org.jetbrains.kotlin.android") version "2.2.20"
}

android {
    // Fixed by the symbols src/jni.rs exports (Java_com_blockcast_amt_<Class>_<method>).
    namespace = "com.blockcast.amt"
    compileSdk = 36

    defaultConfig {
        minSdk = 21
    }

    // The native library is not built here. Put the per-ABI libamt_protocol.so from
    // `make jni` (or the CI artifact) under src/main/jniLibs/<abi>/ and it is packaged
    // into the AAR; see README.md.

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
    testImplementation("junit:junit:4.13.2")
}
