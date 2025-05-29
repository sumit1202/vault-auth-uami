package com.example.vault.configuration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "vault.uami")
public class VaultUamiAuthProperties {

  private String uri;
  private String namespace;
  private String role;
  private String resource;
  private String clientId;

  public VaultUamiAuthProperties() {}

  public VaultUamiAuthProperties(
      String uri, String namespace, String clientId, String resource, String role) {
    this.uri = uri;
    this.namespace = namespace;
    this.clientId = clientId;
    this.resource = resource;
    this.role = role;
  }

  public String getUri() {
    return uri;
  }

  public void setUri(String uri) {
    this.uri = uri;
  }

  public String getNamespace() {
    return namespace;
  }

  public void setNamespace(String namespace) {
    this.namespace = namespace;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(String clientId) {
    this.clientId = clientId;
  }

  public String getResource() {
    return resource;
  }

  public void setResource(String resource) {
    this.resource = resource;
  }

  public String getRole() {
    return role;
  }

  public void setRole(String role) {
    this.role = role;
  }
}
