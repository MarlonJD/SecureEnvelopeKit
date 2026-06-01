import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("org.jetbrains.kotlin.jvm")
    `java-library`
}

group = providers.gradleProperty("GROUP").get()
version = providers.gradleProperty("VERSION_NAME").get()

// Product-independent envelope core. It depends only on the JVM's JCA crypto
// providers (javax.crypto / java.security), which are present identically on
// Android, so this Kotlin/JVM library is consumed directly by Android apps.
// It deliberately has no Android-framework dependency (no Context, Keystore,
// storage, networking, or ML-KEM), which keeps it testable on the JVM.
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

tasks.withType<Test>().configureEach {
    useJUnit()
    // The shared cross-platform fixtures live at the repository root under
    // fixtures/. rootProject lives at platforms/android, so go up two levels.
    systemProperty(
        "secureEnvelopeFixturesDir",
        rootProject.layout.projectDirectory.dir("../../fixtures").asFile.absolutePath,
    )
}
