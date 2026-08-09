/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.httpbasics;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "http-basics.hints.http_basic_quiz.1",
  "http-basics.hints.http_basic_quiz.2",
  "http-basics.hints.http_basic_quiz.3"
})
public class HttpBasicsQuiz implements AssignmentEndpoint {

  private static final String MAGIC_NUMBER = "magicNumber";

  private final LessonSession lessonSession;
  private final SecureRandom random = new SecureRandom();

  public HttpBasicsQuiz(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @GetMapping("/HttpBasics/magic-number")
  @ResponseBody
  public String magicNumber() {
    // minted here and kept in the session, so the browser never decides what the answer is
    String magicNumber = String.valueOf(random.nextInt(100) + 1);
    lessonSession.setValue(MAGIC_NUMBER, magicNumber);
    return magicNumber;
  }

  @PostMapping("/HttpBasics/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String answer, @RequestParam String magic_answer) {
    String magicNumber = (String) lessonSession.getValue(MAGIC_NUMBER);

    if (!"POST".equalsIgnoreCase(answer)) {
      return failed(this).feedback("http-basics.incorrect").build();
    }
    if (magicNumber == null || !magicNumber.equals(magic_answer)) {
      return failed(this).feedback("http-basics.magic").build();
    }
    return success(this).build();
  }
}
