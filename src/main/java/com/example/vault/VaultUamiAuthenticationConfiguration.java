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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestTemplate;

/**
 * Spring configuration for Vault authentication using Azure User Assigned Managed Identity (UAMI)
 * via Entra ID.
 *
 * <p>Registers a custom {@link ClientAuthentication} implementation that authenticates to Vault
 * using an Azure UAMI access token, obtained from the Entra ID. This configuration is registered as
 * a {@link BootstrapRegistryInitializer} to ensure authentication is available during the bootstrap
 * phase, allowing Vault secrets to be fetched early.
 */
@Configuration
public class VaultUamiAuthenticationConfiguration implements BootstrapRegistryInitializer {

  private static final Logger logger =
      LoggerFactory.getLogger(VaultUamiAuthenticationConfiguration.class);

  /**
   * Registers the custom Vault UAMI authentication with the Spring bootstrap registry.
   *
   * @param registry the bootstrap registry
   */
  @Override
  public void initialize(BootstrapRegistry registry) {
    registry.register(ClientAuthentication.class, context -> vaultUamiAuthentication());
  }

  /**
   * Provides a {@link ClientAuthentication} bean that uses UAMI via Entra ID.
   *
   * @return a custom {@link ClientAuthentication} implementation
   */
  @Bean
  public ClientAuthentication vaultUamiAuthentication() {
    return new VaultUamiAuthentication();
  }

  /**
   * Custom {@link ClientAuthentication} implementation that authenticates to Vault using a JWT
   * obtained from Azure UAMI via Entra ID.
   */
  static class VaultUamiAuthentication implements ClientAuthentication {

    private static final Logger logger = LoggerFactory.getLogger(VaultUamiAuthentication.class);

    /** The Vault server URI, injected from configuration. */
    @Value("${spring.cloud.vault.uri}")
    private String vaultUri;

    /** The Vault Azure authentication role, injected from configuration. */
    @Value("${vault.auth.azure.role}")
    private String vaultRole;

    /** The Azure resource ID for Vault authentication, injected from configuration. */
    @Value("${vault.auth.azure.resource-id}")
    private String vaultResourceId;

    /**
     * Performs authentication to Vault using Azure UAMI via Entra ID.
     *
     * <ol>
     *   <li>Retrieves an access token from the Azure Instance Metadata Service (IMDS).
     *   <li>Sends the access token to Vault's Azure authentication endpoint.
     *   <li>Parses and returns the Vault client token.
     * </ol>
     *
     * @return a {@link VaultToken} representing the authenticated session
     * @throws RuntimeException if authentication fails at any step
     */
    @Override
    public VaultToken login() {
      logger.info("Attempting to authenticate to vault using UAMI via Entra ID...");
      try {
        // 1. Retrieve the access token from UAMI via Entra ID
        String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
        String identityHeader = System.getenv("IDENTITY_HEADER");
        String apiVersion = "2019-08-01";
        String tokenUrl =
            String.format(
                "%s?resource=%s&api-version=%s", identityEndpoint, vaultResourceId, apiVersion);

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-IDENTITY-HEADER", identityHeader);
        HttpEntity<String> tokenRequest = new HttpEntity<>(headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<String> tokenResponse =
            restTemplate.exchange(tokenUrl, HttpMethod.GET, tokenRequest, String.class);

        if (!tokenResponse.getStatusCode().is2xxSuccessful() || tokenResponse.getBody() == null) {
          throw new RuntimeException(
              "Failed to retrieve access token from UAMI via Entra ID: "
                  + tokenResponse.getStatusCode());
        }

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(tokenResponse.getBody());
        String accessToken = rootNode.path("access_token").asText();
        logger.debug("Successfully retrieved access token from UAMI via Entra ID.");

        // 2. Construct the authentication request for vault
        String vaultAuthUrl = vaultUri + "/v1/auth/azure/login";
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("role", vaultRole);
        requestBody.put("jwt", accessToken);

        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Map<String, String>> authRequest = new HttpEntity<>(requestBody, authHeaders);

        // 3. Send the authentication request to vault
        ResponseEntity<String> authResponse =
            restTemplate.exchange(vaultAuthUrl, HttpMethod.POST, authRequest, String.class);

        if (!authResponse.getStatusCode().is2xxSuccessful() || authResponse.getBody() == null) {
          throw new RuntimeException(
              "Failed to authenticate to vault: " + authResponse.getStatusCode());
        }

        // 4. Handle the authentication response from vault
        JsonNode authRootNode = mapper.readTree(authResponse.getBody());
        String clientToken = authRootNode.path("auth").path("client_token").asText();
        logger.info("Successfully authenticated to vault.");
        return VaultToken.of(clientToken);

      } catch (Exception e) {
        logger.error(
            "Error during vault authentication using UAMI via Entra ID: {}", e.getMessage(), e);
        throw new RuntimeException("vault authentication failed: " + e.getMessage(), e);
      }
    }
  }
}
