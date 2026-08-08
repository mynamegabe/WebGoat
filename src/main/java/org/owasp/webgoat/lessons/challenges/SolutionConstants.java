/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  // A password that ships as a literal in the source is not a secret: anyone reading the
  // repository knows it. The unpredictable part is generated when the server starts, and the
  // "1234" placeholder is kept so the challenge still substitutes its pincode into it.
  String PASSWORD =
      "!!webgoat_admin_" + java.util.UUID.randomUUID().toString().replace("-", "") + "_1234!!";
}
