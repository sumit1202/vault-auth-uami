package com.example.vault.configuration;

import com.example.vault.delegate.VaultUamiAuthentication;
import com.example.vault.service.UamiAuthService;
import java.io.InputStream;
import java.util.Map;
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
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.client.RestTemplateBuilder;
import org.springframework.vault.client.VaultEndpoint;
import org.springframework.vault.config.AbstractVaultConfiguration.ClientFactoryWrapper;
import org.yaml.snakeyaml.Yaml;

/** Registers UAMI Vault authentication and HTTP client configuration. */
@Configuration
public class VaultUamiAuthenticationConfiguration implements BootstrapRegistryInitializer {

  private static final Logger logger =
      LoggerFactory.getLogger(VaultUamiAuthenticationConfiguration.class);

  /** Registers beans for Vault UAMI authentication. */
  @Override
  public void initialize(BootstrapRegistry registry) {
    String profile = System.getenv("SPRING_PROFILES_ACTIVE");
    profile = (profile == null) ? System.getProperty("spring.profiles.active", "") : profile;

    String finalProfile = profile;
    registry.register(
        VaultUamiAuthProperties.class, context -> getVaultUamiAuthProperties(finalProfile));
    registry.register(ClientFactoryWrapper.class, getClientFactoryWrapper());
    registry.register(RestTemplateBuilder.class, getRestTemplateBuilder());
    registry.register(
        ClientAuthentication.class,
        ctx ->
            new VaultUamiAuthentication(
                new UamiAuthService(
                    ctx.get(VaultUamiAuthProperties.class).getUri(),
                    ctx.get(VaultUamiAuthProperties.class).getNamespace(),
                    ctx.get(VaultUamiAuthProperties.class).getRole(),
                    ctx.get(VaultUamiAuthProperties.class).getResource(),
                    ctx.get(VaultUamiAuthProperties.class).getClientId())));
    logger.info(
        "In profile - {} : VaultUamiAuthentication registered in BootstrapRegistry", finalProfile);
  }

  /** Supplies VaultUamiAuthProperties after parsing and binding profile-specific Yml */
  private VaultUamiAuthProperties getVaultUamiAuthProperties(String finalProfile) {
    String appYmlWithProfile = "application-" + finalProfile + ".yml";
    ClassPathResource resource = new ClassPathResource(appYmlWithProfile);
    try (InputStream in = resource.getInputStream()) {
      Yaml yaml = new Yaml();
      Map<String, Object> yamlMap = yaml.load(in);
      Map<String, Object> vaultMap = (Map<String, Object>) yamlMap.get("vault");
      if (vaultMap == null || !(vaultMap.get("uami") instanceof Map)) {
        throw new IllegalStateException("Missing 'vault.uami' section in " + appYmlWithProfile);
      }
      Map<String, Object> uamiMap = (Map<String, Object>) vaultMap.get("uami");
      VaultUamiAuthProperties props = new VaultUamiAuthProperties();
      props.setUri(uamiMap.get("uri").toString());
      props.setNamespace(uamiMap.get("namespace").toString());
      props.setClientId(uamiMap.get("client-id").toString());
      props.setResource(uamiMap.get("resource").toString());
      props.setRole(uamiMap.get("role").toString());
      return props;
    } catch (Exception e) {
      throw new RuntimeException(e);
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
