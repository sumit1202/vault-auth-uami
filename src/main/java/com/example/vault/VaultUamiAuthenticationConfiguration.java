package com.example.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.BootstrapRegistry;
import org.springframework.boot.BootstrapRegistryInitializer;
import org.springframework.boot.web.client.RestTemplateBuilder; // Import RestTemplateBuilder
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestClientException; // Import RestClientException for more
// specific error handling
import org.springframework.web.client.RestTemplate;

@Configuration
public class VaultUamiAuthenticationConfiguration implements BootstrapRegistryInitializer {

  private static final Logger logger =
      LoggerFactory.getLogger(VaultUamiAuthenticationConfiguration.class);

  // Inject @Value properties directly into the configuration class (Spring-managed)
  @Value("${spring.cloud.vault.uri}")
  private String vaultUri;

  @Value("${vault.auth.azure.role}")
  private String vaultRole;

  @Value("${vault.auth.azure.resource-id}")
  private String vaultResourceId;

  @Value("${vault.auth.azure.client-id}")
  private String clientId;

  /**
   * Registers a default RestTemplate bean in the BootstrapRegistry. This RestTemplate will pick up
   * SSL/TLS settings from application.yml.
   */
  @Bean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder.build();
  }

  /**
   * Registers the custom Vault UAMI authentication with the Spring bootstrap registry. This method
   * ensures authentication is available early in the application lifecycle.
   */
  @Override
  public void initialize(BootstrapRegistry registry) {
    // Register RestTemplate first so it's available for injection into ClientAuthentication
    registry.register(
        RestTemplate.class,
        context -> context.get(RestTemplate.class)); // Get the RestTemplate bean defined above

    registry.register(
        ClientAuthentication.class,
        context -> {
          // Retrieve the RestTemplate instance from the BootstrapRegistry context
          RestTemplate restTemplate = context.get(RestTemplate.class);

          // Pass all injected @Value properties and the RestTemplate to the custom authenticator's
          // constructor
          return new VaultUamiAuthentication(
              vaultUri,
              vaultRole,
              vaultResourceId,
              clientId,
              restTemplate // Pass the properly managed RestTemplate
              );
        });
    logger.info("VaultUamiAuthentication registered in BootstrapRegistry.");
  }

  static class VaultUamiAuthentication implements ClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(VaultUamiAuthentication.class);

    // Make these fields final, as they will be injected via the constructor
    private final String vaultUri;
    private final String vaultRole;
    private final String vaultResourceId;
    private final String clientId;
    private final RestTemplate restTemplate;

    // Constructor to receive all required values from the outer configuration class
    public VaultUamiAuthentication(
        String vaultUri,
        String vaultRole,
        String vaultResourceId,
        String clientId,
        RestTemplate restTemplate) {
      this.vaultUri = vaultUri;
      this.vaultRole = vaultRole;
      this.vaultResourceId = vaultResourceId;
      this.clientId = clientId;
      this.restTemplate = restTemplate; // Use the injected RestTemplate
    }

    @Override
    public VaultToken login() {
      logger.info("Attempting to authenticate to Vault using UAMI via Entra ID...");
      try {
        // 1. Retrieve the access token from UAMI via Entra ID
        String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
        String identityHeader = System.getenv("IDENTITY_HEADER");
        String apiVersion = "2017-09-01"; // Azure IMDS API version

        // Input validation for environment variables
        if (identityEndpoint == null || identityEndpoint.isEmpty()) {
          throw new IllegalStateException(
              "IDENTITY_ENDPOINT environment variable is not set or empty.");
        }
        if (identityHeader == null || identityHeader.isEmpty()) {
          throw new IllegalStateException(
              "IDENTITY_HEADER environment variable is not set or empty.");
        }

        // Construct the URL for the Azure IMDS token endpoint.
        // Use 'client_id' as per Azure IMDS documentation for UAMI.
        String vaultTokenUrl =
            String.format(
                "%s?resource=%s&api-version=%s&client_id=%s", // Corrected parameter name
                identityEndpoint, vaultResourceId, apiVersion, clientId);

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-IDENTITY-HEADER", identityHeader); // Required header for IMDS
        HttpEntity<String> tokenRequest = new HttpEntity<>(headers);

        ResponseEntity<String> tokenResponse;
        try {
          tokenResponse =
              restTemplate.exchange(vaultTokenUrl, HttpMethod.GET, tokenRequest, String.class);
        } catch (RestClientException e) {
          throw new RuntimeException(
              "Error fetching access token from Azure IMDS: " + e.getMessage(), e);
        }

        if (!tokenResponse.getStatusCode().is2xxSuccessful() || tokenResponse.getBody() == null) {
          throw new RuntimeException(
              "Failed to retrieve access token from UAMI via Entra ID. Status: "
                  + tokenResponse.getStatusCode()
                  + ", Body: "
                  + tokenResponse.getBody());
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(tokenResponse.getBody());
        String accessToken = rootNode.path("access_token").asText();
        if (accessToken.isEmpty()) {
          throw new RuntimeException("Access token not found in IMDS response from Azure.");
        }
        // Log only a portion of the token for security reasons
        logger.debug(
            "Successfully retrieved access token from UAMI via Entra ID. Token starts with: {}",
            accessToken.substring(0, Math.min(accessToken.length(), 10)));

        // 2. Construct the authentication request for Vault
        // Ensure vaultUri doesn't end with a '/' to prevent double slashes.
        String vaultBaseUri = vaultUri;
        if (vaultBaseUri.endsWith("/")) {
          vaultBaseUri = vaultBaseUri.substring(0, vaultBaseUri.length() - 1);
        }
        String vaultAuthUrl =
            vaultBaseUri + "/v1/auth/azure/login"; // Standard Vault Azure auth path

        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("role", vaultRole); // Vault Azure auth role mapping for policies
        requestBody.put("jwt", accessToken); // The JWT (access token) from Azure

        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> authRequest = new HttpEntity<>(requestBody, authHeaders);

        // 3. Send the authentication request to Vault
        ResponseEntity<String> authResponse;
        try {
          authResponse =
              restTemplate.exchange(vaultAuthUrl, HttpMethod.POST, authRequest, String.class);
        } catch (RestClientException e) {
          throw new RuntimeException(
              "Error sending authentication request to Vault: " + e.getMessage(), e);
        }

        if (!authResponse.getStatusCode().is2xxSuccessful() || authResponse.getBody() == null) {
          throw new RuntimeException(
              "Failed to authenticate to Vault. Status: "
                  + authResponse.getStatusCode()
                  + ", Body: "
                  + authResponse.getBody());
        }

        // 4. Handle the authentication response from Vault
        JsonNode authRootNode = mapper.readTree(authResponse.getBody());
        String clientToken = authRootNode.path("auth").path("client_token").asText();
        if (clientToken.isEmpty()) {
          throw new RuntimeException("Vault client token not found in authentication response.");
        }
        logger.info("Successfully authenticated to Vault using Azure UAMI.");
        return VaultToken.of(clientToken);
      } catch (Exception e) {
        logger.error(
            "Critical error during Vault authentication using UAMI via Entra ID: {}",
            e.getMessage(),
            e);
        throw new RuntimeException("Vault authentication failed: " + e.getMessage(), e);
      }
    }
  }
}
