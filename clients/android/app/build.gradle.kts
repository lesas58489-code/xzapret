import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Read defaults from local.properties (gitignored). Each user can override.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "com.xzap.client"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.xzap.client"
        minSdk = 24
        targetSdk = 34
        versionCode = 2
        versionName = "1.1"
        buildConfigField("String", "XZAP_KEY",         "\"${localProps.getProperty("XZAP_KEY", "")}\"")
        buildConfigField("String", "XZAP_SERVERS",     "\"${localProps.getProperty("XZAP_SERVERS", "151.244.111.186,202.155.11.110,151.245.104.38")}\"")
        buildConfigField("int",    "XZAP_PORT",        localProps.getProperty("XZAP_PORT", "443"))
        buildConfigField("String", "XZAP_WS_FALLBACK", "\"${localProps.getProperty("XZAP_WS_FALLBACK", "")}\"")
    }

    buildFeatures {
        compose     = true
        buildConfig = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.14"
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
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.11.0")
    implementation("androidx.activity:activity-compose:1.8.2")

    val composeBom = platform("androidx.compose:compose-bom:2024.02.02")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.foundation:foundation")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Single unified AAR from /core/go (via gomobile bind): contains
    // forked tun2socks + XZAP core (uTLS, mux, SOCKS5). See build_xzapcore.sh.
    implementation(files("libs/xzapcore.aar"))
}
