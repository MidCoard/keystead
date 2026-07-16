plugins {
    `java-library`
    `maven-publish`
    id("com.diffplug.spotless") version "8.8.0"
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
        vendor = JvmVendorSpec.ADOPTIUM
    }
    modularity.inferModulePath = true
    withSourcesJar()
    withJavadocJar()
}

val classpathTest = sourceSets.create("classpathTest") {
    compileClasspath += sourceSets.main.get().output + configurations.testCompileClasspath.get()
    runtimeClasspath += output + compileClasspath + configurations.testRuntimeClasspath.get()
}

val coreModuleName = "top.focess.keystead.core"
val mainModulePath = sourceSets.main.get().runtimeClasspath
val namedModuleTestClasspath = sourceSets.test.get().runtimeClasspath.minus(mainModulePath)
val namedModuleTestPackages =
    listOf(
        "top.focess.keystead",
        "top.focess.keystead.aigc",
        "top.focess.keystead.crypto",
        "top.focess.keystead.generator",
        "top.focess.keystead.memory",
        "top.focess.keystead.memory.internal",
        "top.focess.keystead.model",
        "top.focess.keystead.module",
        "top.focess.keystead.recovery",
        "top.focess.keystead.security",
        "top.focess.keystead.security.internal",
        "top.focess.keystead.service",
        "top.focess.keystead.store")

dependencies {
    api("org.jspecify:jspecify:1.0.0")
    implementation("com.google.crypto.tink:tink:1.22.0")
    implementation(platform("org.bouncycastle:bc-jdk18on-bom:1.84"))
    implementation("org.bouncycastle:bcpg-jdk18on")
    implementation("org.bouncycastle:bcpkix-jdk18on")
    implementation("org.bouncycastle:bcprov-jdk18on")

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
    classpath = namedModuleTestClasspath
    useJUnitPlatform()
    systemProperty("keystead.coreModule", coreModuleName)
    systemProperty("keystead.modulePath", mainModulePath.asPath)
    systemProperty("keystead.testClassesDir", sourceSets.test.get().output.asPath)
    jvmArgs(
            "--module-path",
            mainModulePath.asPath,
            "--add-modules",
            "$coreModuleName,ALL-MODULE-PATH",
            "--patch-module",
            "$coreModuleName=${sourceSets.test.get().output.asPath}",
            "--add-reads=$coreModuleName=ALL-UNNAMED",
            "--enable-native-access=$coreModuleName")
    namedModuleTestPackages.forEach {
        jvmArgs("--add-opens=$coreModuleName/$it=ALL-UNNAMED")
    }
    testLogging {
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        showExceptions = true
        showCauses = true
        showStackTraces = true
    }
}

tasks.register<Test>("classpathTest") {
    description = "Runs the classpath consumer compatibility fixture."
    group = LifecycleBasePlugin.VERIFICATION_GROUP
    testClassesDirs = classpathTest.output.classesDirs
    classpath = classpathTest.runtimeClasspath
    modularity.inferModulePath = false
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
}

tasks.check {
    dependsOn("classpathTest")
}

publishing {
    publications {
        create<MavenPublication>("core") {
            from(components["java"])
            pom {
                name.set("Keystead Core")
                description.set(
                    "Encrypted local vault library: key derivation, authenticated encryption, " +
                        "typed secret schemas, local persistence, backup, sync, recovery, and key rotation.")
                url.set("https://github.com/MidCoard/keystead")
                scm {
                    url.set("https://github.com/MidCoard/keystead")
                    connection.set("scm:git:https://github.com/MidCoard/keystead.git")
                    developerConnection.set("scm:git:https://github.com/MidCoard/keystead.git")
                }
            }
        }
    }
}
