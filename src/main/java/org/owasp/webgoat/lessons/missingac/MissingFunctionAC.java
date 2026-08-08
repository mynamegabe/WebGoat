/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // A salt that is a literal in the source is known to everyone who can read the source, so the
  // user hashes can be recomputed offline without ever calling the application. Both salts are
  // generated per boot instead, which keeps them unpredictable while staying stable for a run.
  public static final String PASSWORD_SALT_SIMPLE = generateSalt();
  public static final String PASSWORD_SALT_ADMIN = generateSalt();

  private static String generateSalt() {
    byte[] salt = new byte[32];
    new SecureRandom().nextBytes(salt);
    return Base64.getEncoder().encodeToString(salt);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}
