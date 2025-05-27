package com.example.vault.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.vault.support.VaultToken;
import org.springframework.web.client.RestTemplate;

class UamiAuthServiceTests {

  private TestableUamiAuthService service;
  private RestTemplate restTemplate;

  static class TestableUamiAuthService extends UamiAuthService {
    private final Map<String, String> env;

    TestableUamiAuthService(Map<String, String> env) {
      super(
          "https://vault.example.net",
          "vault-namespace",
          "vault-role",
          "vault-resource-id",
          "vault-client-id");
      this.env = env;
    }

    @Override
    protected String getEnv(String key) {
      return env.get(key);
    }

    @Override
    protected RestTemplate createRestTemplate() {
      return super.createRestTemplate();
    }
  }

  @BeforeEach
  void setUp() {
    restTemplate = mock(RestTemplate.class);
  }

  @Test
  void authenticateReturnsVaultTokenOnSuccess() throws Exception {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    String accessTokenJson = "{\"access_token\":\"access-token-value\"}";
    String vaultTokenJson = "{\"auth\":{\"client_token\":\"vault-client-token\"}}";

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(accessTokenJson, HttpStatus.OK));

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(vaultTokenJson, HttpStatus.OK));

    VaultToken token = service.authenticate();

    assertNotNull(token);
    assertEquals("vault-client-token", token.getToken());
  }

  @Test
  void authenticateThrowsWhenAccessTokenResponseIsNot2xx() {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(null, HttpStatus.BAD_REQUEST));

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Failed to retrieve access token"));
  }

  @Test
  void authenticateThrowsWhenVaultTokenResponseIsNot2xx() throws Exception {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    String accessTokenJson = "{\"access_token\":\"access-token-value\"}";

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(accessTokenJson, HttpStatus.OK));

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED));

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Failed to authenticate to vault"));
  }

  @Test
  void authenticateThrowsWhenRestTemplateThrowsException() {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenThrow(new RuntimeException("RestTemplate error"));

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Vault authentication failed"));
  }

  @Test
  void authenticateThrowsWhenIdentityEnvVarsAreMissing() {
    service =
        new TestableUamiAuthService(Map.of()) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(
        ex.getMessage()
            .contains("IDENTITY_ENDPOINT or IDENTITY_HEADER environment variable is missing"));
  }

  @Test
  void authenticateThrowsWhenIdentityEnvVarsAreEmpty() {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "",
                "IDENTITY_HEADER", "")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(
        ex.getMessage()
            .contains("IDENTITY_ENDPOINT or IDENTITY_HEADER environment variable is missing"));
  }

  @Test
  void authenticateThrowsWhenAccessTokenJsonDoesNotContainAccessToken() throws Exception {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    String accessTokenJson = "{\"not_access_token\":\"no-token\"}";

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(accessTokenJson, HttpStatus.OK));

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Vault authentication failed"));
  }

  @Test
  void authenticateThrowsWhenVaultTokenJsonDoesNotContainClientToken() throws Exception {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            return restTemplate;
          }
        };

    String accessTokenJson = "{\"access_token\":\"access-token-value\"}";
    String vaultTokenJson = "{\"auth\":{\"not_client_token\":\"no-token\"}}";

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(accessTokenJson, HttpStatus.OK));

    when(restTemplate.exchange(
            anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class)))
        .thenReturn(new ResponseEntity<>(vaultTokenJson, HttpStatus.OK));

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Vault authentication failed"));
  }

  @Test
  void authenticateThrowsWhenRestTemplateFactoryFailsWithException() {
    service =
        new TestableUamiAuthService(
            Map.of(
                "IDENTITY_ENDPOINT", "http://id-endpoint",
                "IDENTITY_HEADER", "id-header")) {
          @Override
          protected RestTemplate createRestTemplate() {
            throw new RuntimeException("SSL error");
          }
        };

    RuntimeException ex = assertThrows(RuntimeException.class, service::authenticate);
    assertTrue(ex.getMessage().contains("Vault authentication failed"));
  }
}
