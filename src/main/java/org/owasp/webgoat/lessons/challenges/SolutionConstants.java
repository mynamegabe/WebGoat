/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

public interface SolutionConstants {

  // The template is the exercise's own artifact. What used to make it usable was the four digit
  // pincode, which ImageServlet no longer embeds in the picture and no longer draws from a four
  // digit range, so substituting into this template does not produce a working password.
  String PASSWORD = "!!webgoat_admin_1234!!";
}
