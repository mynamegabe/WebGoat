/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();
    response.put("success", false);
    response.put("flag", null);

    // Only a request which provably originates from WebGoat itself is honoured. A request from
    // another site, or one which does not reveal where it came from, is forged and never receives
    // anything back.
    if (RequestOrigin.isSameOrigin(req)) {
      response.put("message", "Appears the request came from the original host");
    } else {
      response.put("message", pluginMessages.getMessage("csrf-request-rejected"));
    }

    return response;
  }
}
