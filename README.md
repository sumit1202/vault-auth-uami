# Vault App: Secure Secret Management with Azure UAMI & Spring Cloud Vault

> **Project Under Development**

## Overview

This project demonstrates secure secret management in a Spring Boot application using HashiCorp Vault, authenticated via
Azure User Assigned Managed Identity (UAMI) and Entra ID. It enables fetching secrets from Vault during the bootstrap
phase, leveraging cloud-native authentication and best practices for secret injection.

## Prerequisites

- Java 17 or later (Java 21 used in this project)
- Spring Boot 3.x
- Spring Cloud Vault dependency
- Maven
- Enterprise HashiCorp Vault
- Azure environment with a configured User Assigned Managed Identity (UAMI)

## Configuration

### 1. Vault Setup

- Enable the Azure authentication method in Vault.
- Configure a Vault role mapped to your Azure UAMI.
- Store secrets in the desired KV backend (e.g., `secret/vault`).

### 2. Environment Variables

Set the following environment variables:

- `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`: Provided by Azure for UAMI authentication

### 3. Application Properties

Edit `src/main/resources/application.properties` as required for your environment.

## Running the Application

```sh
./mvnw spring-boot:run
```

On startup, the application authenticates to Vault using Azure UAMI, retrieves the configured secret, and prints it to
the console.

## Workflow

1. **Bootstrap Phase**
    - Spring Cloud Vault loads configuration from Vault using a custom `ClientAuthentication`.
    - The authentication retrieves a JWT from Azure IMDS using UAMI.
    - The JWT is exchanged for a Vault token via the Azure auth endpoint.

2. **Secret Injection**
    - Secrets from Vault are injected into Spring properties (e.g., `my.secret.from.vault`).
    - The application uses these secrets at runtime.

3. **Failover**
    - If Vault is unavailable, a default value from `bootstrap.yml` or `application.properties` is used (if configured).

## Project Structure

- `VaultApplication.java`: Main Spring Boot application entry point.
- `VaultUamiAuthenticationConfiguration.java`: Custom Vault authentication using Azure UAMI.
- `application.properties`, `bootstrap.yml`: Configuration files for Spring Cloud Vault and secret management.

## References

- [Spring Cloud Vault Documentation](https://docs.spring.io/spring-cloud-vault/docs/current/reference/html/)
- [HashiCorp Vault Azure Auth](https://developer.hashicorp.com/vault/docs/auth/azure)
- [Azure Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

---

_This project is intended for educational and demonstration purposes. Adapt configurations and security settings for
production use._

```