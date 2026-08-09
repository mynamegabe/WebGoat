/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.util.regex.Pattern;

/**
 * Lessons 3 to 5 execute the statement the student types, so each one accepts only the single
 * statement shape it teaches, against its own table. Chaining, comments, unions and sub-queries are
 * refused.
 */
final class LessonQueryGuard {

  private static final Pattern UNSAFE =
      Pattern.compile(";|--|/\\*|\\bunion\\b|\\binto\\b", Pattern.CASE_INSENSITIVE);

  private LessonQueryGuard() {}

  static boolean isUpdateOfEmployees(String query) {
    return isSingleStatement(query, "update\\s+employees\\s+set\\s+[^()]+");
  }

  static boolean isAlterOfEmployees(String query) {
    return isSingleStatement(
        query, "alter\\s+table\\s+employees\\s+[\\w\\s]+(\\(\\s*\\d+\\s*\\))?");
  }

  static boolean isGrantOnGrantRights(String query) {
    return isSingleStatement(query, "grant\\s+[\\w\\s,]+\\s+on\\s+grant_rights\\s+to\\s+\\w+");
  }

  private static boolean isSingleStatement(String query, String shape) {
    String statement = query == null ? "" : query.trim().replaceAll(";+\\s*$", "");
    return !UNSAFE.matcher(statement).find() && statement.matches("(?is)" + shape);
  }
}
