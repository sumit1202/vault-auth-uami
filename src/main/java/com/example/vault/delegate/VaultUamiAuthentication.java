package com.example.vault.delegate;

import com.example.vault.service.UamiAuthService;
import org.springframework.vault.authentication.ClientAuthentication;
import org.springframework.vault.support.VaultToken;

public class VaultUamiAuthentication implements ClientAuthentication {
  private final UamiAuthService authService;

  public VaultUamiAuthentication(UamiAuthService authService) {
    this.authService = authService;
  }

  @Override
  public VaultToken login() {
    return authService.authenticate();
  }
}
