/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.owasp.webgoat.webwolf.requests.WebWolfTraceRepository.Exclusion.contains;
import static org.owasp.webgoat.webwolf.requests.WebWolfTraceRepository.Exclusion.endsWith;

import com.google.common.collect.EvictingQueue;
import com.google.common.collect.Queues;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.boot.actuate.web.exchanges.HttpExchangeRepository;

/**
 * Keep track of all the incoming requests, we are only keeping track of request originating from
 * WebGoat.
 *
 * @author nbaars
 * @since 8/13/17.
 */
public class WebWolfTraceRepository implements HttpExchangeRepository {
  private enum MatchingMode {
    CONTAINS,
    ENDS_WITH,
    EQUALS;
  }

  record Exclusion(String path, MatchingMode mode) {
    public boolean matches(String path) {
      return switch (mode) {
        case CONTAINS -> path.contains(this.path);
        case ENDS_WITH -> path.endsWith(this.path);
        case EQUALS -> path.equals(this.path);
      };
    }

    public static Exclusion contains(String exclusionPattern) {
      return new Exclusion(exclusionPattern, MatchingMode.CONTAINS);
    }

    public static Exclusion endsWith(String exclusionPattern) {
      return new Exclusion(exclusionPattern, MatchingMode.ENDS_WITH);
    }
  }

  /**
   * The buffer is written from every request thread and read while /requests renders, so it needs a
   * thread safe wrapper. EvictingQueue on its own is documented as not thread safe.
   */
  private final Queue<HttpExchange> traces = Queues.synchronizedQueue(EvictingQueue.create(10000));

  private final List<Exclusion> exclusionList =
      List.of(
          contains("/tmpdir"),
          contains("/home"),
          endsWith("/files"),
          contains("/images/"),
          contains("/js/"),
          contains("/webjars/"),
          contains("/requests"),
          contains("/css/"),
          contains("/mail"),
          // WebWolf's own UI and authentication endpoints. These carry session cookies and
          // credentials and never carry lesson data, so they are not recorded at all.
          contains("/login"),
          contains("/logout"),
          contains("/registration"),
          contains("/register.mvc"),
          contains("/csrf/"),
          contains("/jwt"),
          contains("/fileupload"),
          contains("/file-server-location"),
          contains("/error"),
          contains("/favicon"));

  @Override
  public List<HttpExchange> findAll() {
    synchronized (traces) {
      return new ArrayList<>(traces);
    }
  }

  private boolean isInExclusionList(String path) {
    return exclusionList.stream().anyMatch(e -> e.matches(path));
  }

  @Override
  public void add(HttpExchange httpTrace) {
    var path = httpTrace.getRequest().getUri().getPath();
    if (!isInExclusionList(path)) {
      traces.add(httpTrace);
    }
  }
}
