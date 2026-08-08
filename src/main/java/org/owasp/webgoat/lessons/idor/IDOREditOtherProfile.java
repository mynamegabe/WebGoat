/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null) {
      return failed(this).feedback("idor.view.other.profile.failure1").build();
    }

    // Horizontal access control: the identifier in the path and the one in the submitted body are
    // only accepted when they refer to the authenticated user, so another user's profile can not
    // be reached from here.
    if (!authUserId.equals(userId)
        || (userSubmittedProfile.getUserId() != null
            && !authUserId.equals(userSubmittedProfile.getUserId()))) {
      return failed(this).feedback("idor.edit.profile.denied").build();
    }

    // The profile that is updated is always the one belonging to the session, and only the
    // attributes a user owns are taken from the request. The role drives authorization decisions
    // and is therefore never bound from client supplied data.
    UserProfile currentUserProfile = new UserProfile(authUserId);
    currentUserProfile.setColor(userSubmittedProfile.getColor());
    currentUserProfile.setSize(userSubmittedProfile.getSize());
    userSessionData.setValue("idor-updated-own-profile", currentUserProfile);

    return failed(this)
        .feedback("idor.edit.profile.updated")
        .output(currentUserProfile.profileToMap().toString())
        .build();
  }
}
