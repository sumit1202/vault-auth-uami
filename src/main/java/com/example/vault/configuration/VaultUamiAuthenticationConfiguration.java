package com.example.vault.configuration;

import com.example.vault.delegate.VaultUamiAuthentication;
import com.example.vault.service.UamiAuthService;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.BootstrapRegistry;
import org.springframework.boot.BootstrapRegistry.InstanceSupplier;
import org.springframework.boot.BootstrapRegistryInitializer;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.RestTemplateBuilder;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration.ClientFactoryWrapper;

/** Registers UAMI Vault authentication and HTTP client configuration. */
@Configuration
public class VaultUamiAuthenticationConfiguration implements BootstrapRegistryInitializer {

  private static final Logger logger =
      LoggerFactory.getLogger(VaultUamiAuthenticationConfiguration.class);

  /** Registers beans for Vault UAMI authentication if not running in 'local' profile. */
  @Override
  public void initialize(BootstrapRegistry registry) {
    String profiles = System.getProperty("spring.profiles.active", "");
    if (!profiles.contains("local")) {
      registry.register(ClientFactoryWrapper.class, getClientFactoryWrapper());
      registry.register(RestTemplateBuilder.class, getRestTemplateBuilder());
      registry.register(
          ClientAuthentication.class,
          ctx ->
              new VaultUamiAuthentication(
                  new UamiAuthService(
                      "vault.uami.uri",
                      "vault.uami.namespace",
                      "vault.uami.role",
                      "vault.uami.resource-id",
                      "vault.uami.client-id")));
      logger.debug("vaultUamiAuthentication registered in BootstrapRegistry");
    }
  }

  /** Supplies a RestTemplateBuilder with Vault endpoint and namespace. */
  private InstanceSupplier<RestTemplateBuilder> getRestTemplateBuilder() {
    return context ->
        RestTemplateBuilder.builder()
            .requestFactory(context.get(ClientFactoryWrapper.class).getClientHttpRequestFactory())
            .endpointProvider(() -> VaultEndpoint.from("vault.uami.uri"))
            .defaultHeader("X-Vault-Namespace", "vault.uami.namespace");
  }

  /** Supplies a ClientFactoryWrapper with custom SSL configuration. */
  private InstanceSupplier<ClientFactoryWrapper> getClientFactoryWrapper() {
    DefaultClientTlsStrategy tlsStrategy;
    try {
      tlsStrategy =
          new DefaultClientTlsStrategy(
              SSLContexts.custom().loadTrustMaterial(TrustSelfSignedStrategy.INSTANCE).build());
    } catch (Exception e) {
      logger.error("Failed to create TLS strategy: {}", e.getMessage());
      throw new RuntimeException(e);
    }
    var connectionManager =
        PoolingHttpClientConnectionManagerBuilder.create()
            .setTlsSocketStrategy(tlsStrategy)
            .build();
    var httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    return context ->
        new ClientFactoryWrapper(new HttpComponentsClientHttpRequestFactory(httpClient));
  }
}
