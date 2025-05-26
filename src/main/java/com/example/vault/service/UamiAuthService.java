package com.example.vault.service;

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
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestTemplate;

public class UamiAuthService {
  private static final Logger logger = LoggerFactory.getLogger(UamiAuthService.class);

  private final String vaultUri, vaultNamespace, vaultRole, vaultResourceId, vaultClientId;

  public UamiAuthService(
      String vaultUri,
      String vaultNamespace,
      String vaultRole,
      String vaultResourceId,
      String vaultClientId) {
    this.vaultUri = vaultUri;
    this.vaultNamespace = vaultNamespace;
    this.vaultRole = vaultRole;
    this.vaultResourceId = vaultResourceId;
    this.vaultClientId = vaultClientId;
  }

  public VaultToken authenticate() {
    logger.info("Authenticating to vault using UAMI via Entra ID...");
    try {
      RestTemplate restTemplate = createRestTemplate();
      String accessToken = fetchAccessToken(restTemplate);
      String clientToken = fetchVaultToken(restTemplate, accessToken);
      logger.info("Successfully authenticated to vault.");
      return VaultToken.of(clientToken);
    } catch (Exception e) {
      logger.error("Vault authentication failed: {}", e.getMessage(), e);
      throw new RuntimeException("Vault authentication failed: " + e.getMessage(), e);
    }
  }

  private String fetchAccessToken(RestTemplate restTemplate) throws Exception {
    String identityEndpoint = System.getenv("IDENTITY_ENDPOINT");
    String identityHeader = System.getenv("IDENTITY_HEADER");
    String tokenUrl =
        String.format(
            "%s?resource=%s&api-version=2017-09-01&clientId=%s",
            identityEndpoint, vaultResourceId, vaultClientId);

    HttpHeaders headers = new HttpHeaders();
    headers.set("secret", identityHeader);
    ResponseEntity<String> response =
        restTemplate.exchange(tokenUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);

    if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null)
      throw new RuntimeException("Failed to retrieve access token: " + response.getStatusCode());

    return new ObjectMapper().readTree(response.getBody()).path("access_token").asText();
  }

  private String fetchVaultToken(RestTemplate restTemplate, String accessToken) throws Exception {
    String vaultAuthUrl = vaultUri + "/v1/auth/azure/login";
    Map<String, String> requestBody = new HashMap<>();
    requestBody.put("role", vaultRole);
    requestBody.put("jwt", accessToken);

    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Vault-Namespace", vaultNamespace);
    headers.setContentType(MediaType.APPLICATION_JSON);
    headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

    ResponseEntity<String> response =
        restTemplate.exchange(
            vaultAuthUrl, HttpMethod.POST, new HttpEntity<>(requestBody, headers), String.class);

    if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null)
      throw new RuntimeException("Failed to authenticate to vault: " + response.getStatusCode());

    return new ObjectMapper()
        .readTree(response.getBody())
        .path("auth")
        .path("client_token")
        .asText();
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
