# Vault App: Secure Secret Management with Azure UAMI and Spring Cloud Vault

## Objective

This project demonstrates secure secret management in a Spring Boot application using HashiCorp Vault, authenticated via
Azure User Assigned Managed Identity (UAMI) and Entra ID. The goal is to fetch secrets from Vault at application
startup, leveraging cloud-native authentication and best practices for secret injection.

## Usage

### Prerequisites

- Java 17 or later
- Maven
- HashiCorp Vault instance (local or remote)
- Azure environment with a configured User Assigned Managed Identity (UAMI)

### Configuration

1. **Vault Setup**
    - Enable the Azure authentication method in Vault.
    - Configure a Vault role mapped to your Azure UAMI.
    - Store secrets in the configured KV backend (default: `secret/vault`).

2. **Environment Variables**
    - `VAULT_ADDR`: Vault server address (e.g., `http://localhost:8200`)
    - `vault_RESOURCE_ID`: Azure resource ID for the UAMI
    - `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`: Provided by Azure for UAMI authentication

3. **Application Properties**
    - Edit `src/main/resources/application.properties` as needed for your environment. (Also look for inline comments
      for more info)

### Running the Application

```
./mvnw spring-boot:run
```

On startup, the application will authenticate to Vault using Azure UAMI, fetch the configured secret, and print it to
the console.

## Working Flow

1. **Bootstrap Phase**
    - Spring Cloud Vault loads configuration from Vault using a custom `ClientAuthentication`.
    - The custom authentication retrieves a JWT from Azure IMDS using UAMI.
    - The JWT is sent to Vault's Azure auth endpoint to obtain a Vault token.

2. **Secret Injection**
    - Secrets from Vault are injected into Spring properties (e.g., `my.secret.from.vault`).
    - The application uses these secrets at runtime, demonstrated by printing the secret on startup.

3. **Failover**
    - If Vault is unavailable, a default value from `bootstrap.yml` or `application.properties` is used (if configured).

## Project Structure

- `VaultApplication.java`: Main Spring Boot application, prints the secret.
- `VaultUamiAuthenticationConfiguration.java`: Custom Vault authentication using Azure UAMI.
- `application.properties` & `bootstrap.yml`: Configuration files for Spring Cloud Vault and secret management.

## References

- [Spring Cloud Vault Documentation](https://docs.spring.io/spring-cloud-vault/docs/current/reference/html/)
- [HashiCorp Vault Azure Auth](https://developer.hashicorp.com/vault/docs/auth/azure)
- [Azure Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)

---
This project is intended for educational and demonstration purposes. Adapt configurations and security settings for
production use.

