package com.example.vault;

import org.springframework.vault.authentication.VaultTokenSupplier;
import org.springframework.vault.support.VaultToken;
import reactor.core.publisher.Mono;

public class Custom implements VaultTokenSupplier {
  @Override
  public Mono<VaultToken> getVaultToken() {
    return null;
  }
}
