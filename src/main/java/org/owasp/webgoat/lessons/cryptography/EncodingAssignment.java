/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.HttpServletRequest;
import java.security.SecureRandom;
import java.util.Base64;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EncodingAssignment implements AssignmentEndpoint {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /*
   * Base64 is an encoding and not encryption, so a credential placed in a response is readable by
   * everyone who receives it. The header handed to the client carries a redacted value and the
   * real one never leaves the server.
   */
  private static final String REDACTED_BASIC_AUTH = getBasicAuth("redacted", "redacted");

  public static String getBasicAuth(String username, String password) {
    return Base64.getEncoder().encodeToString(username.concat(":").concat(password).getBytes());
  }

  @GetMapping(path = "/crypto/encoding/basic", produces = MediaType.TEXT_HTML_VALUE)
  @ResponseBody
  public String getBasicAuth(HttpServletRequest request) {

    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    String username = request.getUserPrincipal().getName();
    if (basicAuth == null) {
      basicAuth = getBasicAuth(username, generatePassword());
      request.getSession().setAttribute("basicAuth", basicAuth);
    }
    return "Authorization: Basic ".concat(REDACTED_BASIC_AUTH);
  }

  private static String generatePassword() {
    byte[] password = new byte[24];
    SECURE_RANDOM.nextBytes(password);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(password);
  }

  @PostMapping("/crypto/encoding/basic-auth")
  @ResponseBody
  public AttackResult completed(
      HttpServletRequest request,
      @RequestParam String answer_user,
      @RequestParam String answer_pwd) {
    String basicAuth = (String) request.getSession().getAttribute("basicAuth");
    if (basicAuth != null
        && answer_user != null
        && answer_pwd != null
        && basicAuth.equals(getBasicAuth(answer_user, answer_pwd))) {
      return success(this).feedback("crypto-encoding.success").build();
    } else {
      return failed(this).feedback("crypto-encoding.empty").build();
    }
  }
}
