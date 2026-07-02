plugins {
    `java-library`
    id("com.diffplug.spotless") version "8.8.0"
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
    withSourcesJar()
}

dependencies {
    api("org.jspecify:jspecify:1.0.0")
    implementation("com.google.crypto.tink:tink:1.22.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

spotless {
    java {
        target("src/**/*.java")
        googleJavaFormat("1.35.0").aosp().reflowLongStrings().formatJavadoc(false)
        formatAnnotations()
    }
}

tasks.test {
    useJUnitPlatform()
}
