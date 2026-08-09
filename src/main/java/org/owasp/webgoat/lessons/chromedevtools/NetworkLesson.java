/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.chromedevtools;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Assignment where the user has to look through an HTTP Request using the Developer Tools and find
 * a specific number.
 *
 * @author TMelzer
 * @since 30.11.18
 */
@RestController
@AssignmentHints({"networkHint1", "networkHint2"})
public class NetworkLesson implements AssignmentEndpoint {

  private static final String NETWORK_NUMBER = "networkNumber";

  private final LessonSession lessonSession;
  private final SecureRandom random = new SecureRandom();

  public NetworkLesson(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @PostMapping(value = "/ChromeDevTools/network", params = "number")
  @ResponseBody
  public AttackResult completed(@RequestParam String number) {
    String networkNumber = (String) lessonSession.getValue(NETWORK_NUMBER);

    if (networkNumber != null && networkNumber.equals(number)) {
      return success(this).feedback("network.success").output("").build();
    } else {
      return failed(this).feedback("network.failed").build();
    }
  }

  @PostMapping(path = "/ChromeDevTools/network", params = "networkNum")
  @ResponseBody
  public ResponseEntity<String> ok() {
    // minted here and kept in the session, so the browser never decides what the answer is
    String networkNumber = String.valueOf(random.nextInt(100));
    lessonSession.setValue(NETWORK_NUMBER, networkNumber);
    return ResponseEntity.ok(networkNumber);
  }
}
