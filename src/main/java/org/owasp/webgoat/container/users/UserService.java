/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.users;

import java.util.List;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.flywaydb.core.Flyway;
import org.owasp.webgoat.container.lessons.Initializable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * @author nbaars
 * @since 3/19/17.
 */
@Service
public class UserService implements UserDetailsService {

  /**
   * The schema name is interpolated into DDL, so only names the registration form itself accepts are
   * allowed here. Identity providers are not bound by that form, so the check is enforced again at
   * the point the name reaches the database.
   */
  private static final Pattern SAFE_SCHEMA_NAME = Pattern.compile("[a-zA-Z0-9-]{1,45}");

  private final UserRepository userRepository;
  private final UserProgressRepository userTrackerRepository;
  private final JdbcTemplate jdbcTemplate;
  private final Function<String, Flyway> flywayLessons;
  private final List<Initializable> lessonInitializables;
  private final PasswordEncoder passwordEncoder;

  @Autowired
  public UserService(
      UserRepository userRepository,
      UserProgressRepository userTrackerRepository,
      JdbcTemplate jdbcTemplate,
      Function<String, Flyway> flywayLessons,
      List<Initializable> lessonInitializables,
      PasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.userTrackerRepository = userTrackerRepository;
    this.jdbcTemplate = jdbcTemplate;
    this.flywayLessons = flywayLessons;
    this.lessonInitializables = lessonInitializables;
    this.passwordEncoder = passwordEncoder == null ? new BCryptPasswordEncoder() : passwordEncoder;
  }

  public UserService(
      UserRepository userRepository,
      UserProgressRepository userTrackerRepository,
      JdbcTemplate jdbcTemplate,
      Function<String, Flyway> flywayLessons,
      List<Initializable> lessonInitializables) {
    this(
        userRepository,
        userTrackerRepository,
        jdbcTemplate,
        flywayLessons,
        lessonInitializables,
        new BCryptPasswordEncoder());
  }

  @Override
  public WebGoatUser loadUserByUsername(String username) throws UsernameNotFoundException {
    WebGoatUser webGoatUser = userRepository.findByUsername(username);
    if (webGoatUser == null) {
      throw new UsernameNotFoundException("User not found");
    } else {
      webGoatUser.createUser();
      // TODO maybe better to use an event to initialize lessons to keep dependencies low
      lessonInitializables.forEach(l -> l.initialize(webGoatUser));
    }
    return webGoatUser;
  }

  public void addUser(String username, String password) {
    if (!SAFE_SCHEMA_NAME.matcher(username).matches()) {
      throw new IllegalArgumentException("Invalid username");
    }
    // get user if there exists one by the name
    var userAlreadyExists = userRepository.existsByUsername(username);
    if (userAlreadyExists) {
      // never silently replace the stored credentials of an account that already exists
      return;
    }
    var webGoatUser = userRepository.save(new WebGoatUser(username, passwordEncoder.encode(password)));

    userTrackerRepository.save(new UserProgress(username));
    createLessonsForUser(webGoatUser);
  }

  private void createLessonsForUser(WebGoatUser webGoatUser) {
    jdbcTemplate.execute(
        "CREATE SCHEMA " + quoteIdentifier(webGoatUser.getUsername()) + " authorization dba");
    flywayLessons.apply(webGoatUser.getUsername()).migrate();
  }

  private static String quoteIdentifier(String identifier) {
    return "\"" + identifier.replace("\"", "\"\"") + "\"";
  }

  public List<WebGoatUser> getAllUsers() {
    return userRepository.findAll();
  }
}
