// SPDX-License-Identifier: AGPL-3.0-only
import org.gradle.api.artifacts.dsl.LockMode

plugins {
    kotlin("jvm") version "2.4.20"
    application
}

val contractsVersion = "1.0.0-ci.42.1"
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
    doFirst {
        require(System.getenv("CI") != "true") { "Consumer runtime tests are local opt-in only." }
    }
}

tasks.register("resolveDependencies") {
    doLast { configurations.filter { it.isCanBeResolved }.forEach { it.resolve() } }
}

// Project licence metadata is verified independently of the root LICENSE.
extra["spdxLicense"] = "AGPL-3.0-only"
extra["licenceBoundary"] = "AGPL"

gradle.projectsEvaluated {
    val declarations = rootProject.allprojects.sortedBy { it.path }.map { owned ->
        require(owned.projectDir.canonicalFile.toPath().startsWith(rootDir.canonicalFile.toPath())) {
            "AFL002: Project escapes this build: ${owned.path}"
        }
        require(owned.extra.has("spdxLicense") && owned.extra["spdxLicense"] == "AGPL-3.0-only" &&
                owned.extra.has("licenceBoundary") && owned.extra["licenceBoundary"] == "AGPL") {
            "AFL001: Missing or incorrect AGPL licence declaration: ${owned.path}"
        }
        val references = owned.configurations.flatMap { configuration ->
            configuration.dependencies.withType<org.gradle.api.artifacts.ProjectDependency>().map { it.path }
        }.distinct().sorted()
        references.forEach { reference ->
            val target = rootProject.project(reference)
            require(target.extra.has("licenceBoundary") && target.extra["licenceBoundary"] == "AGPL") {
                "AFL003: Undeclared project reference: ${owned.path} -> ${target.path}"
            }
        }
        mapOf("project" to owned.path, "spdxLicense" to owned.extra["spdxLicense"],
              "licenceBoundary" to owned.extra["licenceBoundary"], "projectReferences" to references)
    }
    val report = rootProject.layout.buildDirectory.file("reports/licence-boundary.json").get().asFile
    report.parentFile.mkdirs()
    report.writeText(groovy.json.JsonOutput.prettyPrint(groovy.json.JsonOutput.toJson(declarations)) + "\n")
}
