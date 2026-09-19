plugins {
    application
    alias(libs.plugins.lombok)
}

group = "io.allitov"
version = "1.0.0"

repositories {
    mavenCentral()
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(25))
    }
}

dependencies {
    implementation(libs.log4j.slf4j)

    testImplementation(libs.assertj)
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.launcher)
}

tasks.run {
    mainClass.set("io.allitov.Main")
    standardInput = System.`in`
}

tasks.test {
    useJUnitPlatform()
}
