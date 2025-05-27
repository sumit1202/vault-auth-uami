package com.example.vault.delegate;

import com.example.vault.service.UamiAuthService;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.support.VaultToken;

/** Vault ClientAuthentication implementation using UAMI. */
public class VaultUamiAuthentication implements ClientAuthentication {
  private final UamiAuthService authService;

  /**
   * @param authService UAMI authentication service
   */
  public VaultUamiAuthentication(UamiAuthService authService) {
    this.authService = authService;
  }

  /**
   * Performs login to Vault using UAMI.
   *
   * @return VaultToken
   */
  @Override
  public VaultToken login() {
    return authService.authenticate();
  }
}
