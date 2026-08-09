/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.util.UUID;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Part of the password reset assignment. Used to send the e-mail.
 *
 * @author nbaars
 * @since 8/20/17.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String resetLinkHost;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.host}") String webGoatHost,
      @Value("${webgoat.port}") String webGoatPort) {
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    // Where this application actually answers, read from its own configuration rather than from
    // the client-controlled Host header of the request asking for the reset.
    this.resetLinkHost = webGoatHost + ":" + webGoatPort;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.resetLinks.add(resetLink);
    ResetLinkAssignment.resetLinkToEmail.put(resetLink, email);
    try {
      // The address in the mail is this application's own, never the one the request claimed to
      // be, so the Host header cannot decide where a reset link points.
      sendMailToUser(email, resetLink);
    } catch (Exception e) {
      return informationMessage(this).output("E-mail can't be send. please try again.").build();
    }
    // The answer is the same for every address, so this endpoint neither reveals whether an
    // account exists nor hands out a reset link for somebody else's account.
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Password reset requested")
            .contents(String.format(ResetLinkAssignment.TEMPLATE, resetLinkHost, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }
}
