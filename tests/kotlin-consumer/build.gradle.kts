// SPDX-License-Identifier: AGPL-3.0-only
import org.gradle.api.artifacts.dsl.LockMode

plugins {
    kotlin("jvm") version "2.4.20"
    application
}

val contractsVersion = "1.0.0-ci.36.1"
kotlin { jvmToolchain(17) }
application { mainClass.set("io.github.arcforges.cloud.verification.MainKt") }
tasks.processResources {
    inputs.property("contractsVersion", contractsVersion)
    filesMatching("verification.properties") { expand("contractsVersion" to contractsVersion) }
}
dependencies {
    implementation("io.github.arcforges:contracts-connect-client:$contractsVersion")
    implementation("com.connectrpc:connect-kotlin-okhttp:0.9.0")
    implementation("com.connectrpc:connect-kotlin-google-javalite-ext:0.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("com.google.code.gson:gson:2.14.0")
}
dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions { allWarningsAsErrors.set(true) }
}
tasks.register<JavaExec>("deadlineTest") {
    dependsOn(tasks.classes)
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass.set(application.mainClass)
    args("--self-test")
}
tasks.check { dependsOn("deadlineTest") }
tasks.register("resolveDependencies") {
    doLast { configurations.filter { it.isCanBeResolved }.forEach { it.resolve() } }
}
