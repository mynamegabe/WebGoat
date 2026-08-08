/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    if (username.contains("<p>") || username.contains("<div>")) {
      return failed(this).output("Try to think of something simple ").build();
    }
    // A log entry has to stay on the line it was written to and may never be interpreted as
    // markup, otherwise the user can forge extra entries. Line endings are replaced and the value
    // is encoded before it is added to the log.
    String logEntry = HtmlUtils.htmlEscape(username.replace('\r', ' ').replace('\n', ' '));
    int lineBreak = logEntry.indexOf("<br/>");
    if (lineBreak >= 0 && lineBreak < logEntry.indexOf("admin")) {
      return success(this).output(logEntry).build();
    }
    return failed(this).output(logEntry).build();
  }
}
