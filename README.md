# Vault Azure UAMI Authentication leveraging Spring Cloud Vault - Example

This project demonstrates secure authentication to Enterprise HashiCorp Vault using Azure Entra ID User Assigned Managed
Identity (UAMI) and secret retrieval in a Spring Boot application.

## Features

- Authenticate to Vault using Azure UAMI and Entra ID.
- Custom `UamiAuthService` for token exchange.
- Spring Cloud Vault integration.
- Profile-based configuration via YAML.

## Configuration

Edit `src/main/resources/application.yml`:

```yaml
vault:
  uami:
    uri: <VAULT_URI>
    namespace: <VAULT_NAMESPACE>
    role: <VAULT_ROLE>
    resource: <VAULT_RESOURCE>
    client-id: <AZURE_CLIENT_ID>
```

Set the following environment variables for Azure identity:

- `IDENTITY_ENDPOINT`
- `IDENTITY_HEADER`

## Usage

1. Build the project:
   ```sh
   ./mvnw clean install
   ```

2. Run the application:
   ```sh
   java -jar target/vault-0.0.1-SNAPSHOT.jar
   ```

## Testing

Unit tests for authentication logic are provided:

```sh
./mvnw test
```

## Structure

- `UamiAuthService`: Handles Azure and Vault token exchange.
- `VaultUamiAuthentication`: Integrates with Spring Vault.
- `VaultUamiAuthenticationConfiguration`: Registers authentication beans.



