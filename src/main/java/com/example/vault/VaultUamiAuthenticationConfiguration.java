package com.example.vault;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.BootstrapRegistry;
import org.springframework.boot.BootstrapRegistryInitializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestTemplate;

@Configuration
public class VaultUamiAuthenticationConfiguration implements BootstrapRegistryInitializer {

  private static final Logger logger =
      LoggerFactory.getLogger(VaultUamiAuthenticationConfiguration.class);

  @Override
  public void initialize(BootstrapRegistry registry) {
    String profiles = System.getProperty("spring.profiles.active", "");
    if (!profiles.contains("local")) {
      registry.register(RestTemplate.class, ctx -> createRestTemplate());
      registry.register(
          ClientAuthentication.class,
          ctx -> {
            Environment env = ctx.get(Environment.class);
            return new VaultUamiAuthentication(
                env.getProperty("spring.cloud.vault.uri"),
                env.getProperty("spring.cloud.vault.namespace"),
                env.getProperty("vault.auth.azure.role"),
                env.getProperty("vault.auth.azure.resource-id"),
                env.getProperty("vault.auth.azure.client-id"),
                ctx.get(RestTemplate.class));
          });
      logger.info("vaultUamiAuthentication registered in BootstrapRegistry");
    }
  }

  static class VaultUamiAuthentication implements ClientAuthentication {
    private static final Logger logger = LoggerFactory.getLogger(VaultUamiAuthentication.class);

    private final String vaultUri, vaultNamespace, vaultRole, vaultResourceId, vaultClientId;
    private final RestTemplate restTemplate;

    VaultUamiAuthentication(
        String vaultUri,
        String vaultNamespace,
        String vaultRole,
        String vaultResourceId,
        String vaultClientId,
        RestTemplate restTemplate) {
      this.vaultUri = vaultUri;
      this.vaultNamespace = vaultNamespace;
      this.vaultRole = vaultRole;
      this.vaultResourceId = vaultResourceId;
      this.vaultClientId = vaultClientId;
      this.restTemplate = restTemplate;
    }

    @Override
    public VaultToken login() {
      logger.info("Authenticating to vault using UAMI via Entra ID...");
      try {
        String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
        String identityHeader = System.getenv("IDENTITY_HEADER");
        String vaultTokenUrl =
            String.format(
                "%s?resource=%s&api-version=2017-09-01&clientId=%s",
                identityEndpoint, vaultResourceId, vaultClientId);

        HttpHeaders headers = new HttpHeaders();
        headers.set("secret", identityHeader);
        ResponseEntity<String> identityTokenResponse =
            restTemplate.exchange(
                vaultTokenUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);

        if (!identityTokenResponse.getStatusCode().is2xxSuccessful()
            || identityTokenResponse.getBody() == null)
          throw new RuntimeException(
              "Failed to retrieve access token: " + identityTokenResponse.getStatusCode());

        String accessToken =
            new ObjectMapper()
                .readTree(identityTokenResponse.getBody())
                .path("access_token")
                .asText();

        String vaultAuthUrl = vaultUri + "/v1/auth/azure/login";
        Map<String, String> requestBody = new HashMap<>();
        requestBody.put("role", vaultRole);
        requestBody.put("jwt", accessToken);

        HttpHeaders authHeaders = new HttpHeaders();
        authHeaders.add("X-Vault_Namespace", vaultNamespace);
        authHeaders.setContentType(MediaType.APPLICATION_JSON);
        authHeaders.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        ResponseEntity<String> authResponse =
            restTemplate.exchange(
                vaultAuthUrl,
                HttpMethod.POST,
                new HttpEntity<>(requestBody, authHeaders),
                String.class);

        if (!authResponse.getStatusCode().is2xxSuccessful() || authResponse.getBody() == null)
          throw new RuntimeException(
              "Failed to authenticate to vault: " + authResponse.getStatusCode());

        String clientToken =
            new ObjectMapper()
                .readTree(authResponse.getBody())
                .path("auth")
                .path("client_token")
                .asText();
        logger.info("Successfully authenticated to vault.");
        return VaultToken.of(clientToken);
      } catch (Exception e) {
        logger.error("Vault authentication failed: {}", e.getMessage(), e);
        throw new RuntimeException("Vault authentication failed: " + e.getMessage(), e);
      }
    }
  }

  private RestTemplate createRestTemplate() {
    try {
      var tlsStrategy =
          new DefaultClientTlsStrategy(
              SSLContexts.custom().loadTrustMaterial(TrustSelfSignedStrategy.INSTANCE).build());
      var connectionManager =
          PoolingHttpClientConnectionManagerBuilder.create()
              .setTlsSocketStrategy(tlsStrategy)
              .build();
      var httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
      return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
    } catch (Exception e) {
      logger.error("SSL configuration failed: {}", e.getMessage(), e);
      throw new RuntimeException("Failed to configure RestTemplate with SSL: " + e.getMessage(), e);
    }
  }
}
