// Kotlin Gradle build script with embedded credentials

plugins {
    kotlin("jvm") version "1.9.20"
    id("org.springframework.boot") version "3.2.0"
}

repositories {
    mavenCentral()
    maven {
        url = uri("https://maven.securecorp.com/releases")
        credentials {
            username = "admin"
            password = "Sup3rS3cr3t_P@ssw0rd_2024"
        }
    }
}

val dbUrl = "jdbc:postgresql://db.prod.internal:5432/payments?user=admin&password=Passw0rd!"
val adminEmail = "devops@securecorp.com"
val contactPhone = "+1-555-867-5309"
val serverIp = "10.240.0.15"
