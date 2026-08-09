/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import lombok.Getter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * The password behind the {xor} string the cryptography lesson shows. It is drawn once per boot so
 * the answer is not readable in the source, and rendered into the page so the exercise is unchanged.
 */
@Component
@ControllerAdvice
@Getter
public class XorEncodedPassword {

  // WebSphere's {xor} obfuscation is a single-byte xor followed by base64
  private static final byte XOR_MASK = 0x5f;
  private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";

  private final String password;
  private final String encoded;

  public XorEncodedPassword() {
    this.password = randomPassword();
    byte[] raw = password.getBytes(StandardCharsets.UTF_8);
    byte[] masked = new byte[raw.length];
    for (int i = 0; i < raw.length; i++) {
      masked[i] = (byte) (raw[i] ^ XOR_MASK);
    }
    this.encoded = "{xor}" + Base64.getEncoder().encodeToString(masked);
  }

  @ModelAttribute("xorEncodedPassword")
  public String xorEncodedPassword() {
    return encoded;
  }

  private static String randomPassword() {
    var random = new SecureRandom();
    var builder = new StringBuilder();
    for (int i = 0; i < 16; i++) {
      builder.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
    }
    return builder.toString();
  }
}
