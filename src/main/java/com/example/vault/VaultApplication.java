package com.example.vault;

import java.util.logging.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VaultApplication implements CommandLineRunner {

  @Value("${my.secret.from.vault}")
  private String secretFromVault;

  public static void main(String[] args) {
    SpringApplication.run(VaultApplication.class, args);
  }

  @Override
  public void run(String... args) throws Exception {

    Logger logger = Logger.getAnonymousLogger();
    logger.info(secretFromVault);
    System.out.println("Retrieved secret from vault: " + secretFromVault);
  }
}
