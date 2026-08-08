/*
 * SPDX-FileCopyrightText: Copyright © 2016 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@RestController
@Slf4j
public class Salaries {

  private static final String[] VISIBLE_FIELDS = {
    "UserID", "FirstName", "LastName", "SSN", "Salary"
  };

  @Value("${webgoat.user.directory}")
  private String webGoatHomeDirectory;

  @PostConstruct
  public void copyFiles() {
    ClassPathResource classPathResource = new ClassPathResource("lessons/employees.xml");
    File targetDirectory = new File(webGoatHomeDirectory, "/ClientSideFiltering");
    if (!targetDirectory.exists()) {
      targetDirectory.mkdir();
    }
    try {
      FileCopyUtils.copy(
          classPathResource.getInputStream(),
          new FileOutputStream(new File(targetDirectory, "employees.xml")));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @GetMapping("clientSideFiltering/salaries")
  @ResponseBody
  public List<Map<String, Object>> invoke(
      @RequestParam(value = "userId", required = false) String userId) {
    File d = new File(webGoatHomeDirectory, "ClientSideFiltering/employees.xml");
    List<Map<String, Object>> json = new ArrayList<>();

    // The caller only ever gets the records it is entitled to see. Returning every employee and
    // leaving the page to hide the rest publishes the salary and the SSN of staff the caller does
    // not manage to anyone who reads the response instead of the rendered table.
    if (userId == null || userId.isBlank()) {
      return json;
    }

    XPathFactory factory = XPathFactory.newInstance();
    XPath path = factory.newXPath();

    try (InputStream is = new FileInputStream(d)) {
      InputSource inputSource = new InputSource(is);
      NodeList employees =
          (NodeList) path.evaluate("/Employees/Employee", inputSource, XPathConstants.NODESET);

      for (int i = 0; i < employees.getLength(); i++) {
        Node employee = employees.item(i);
        if (!isVisibleTo(employee, userId)) {
          continue;
        }
        Map<String, Object> employeeJson = new HashMap<>();
        for (String field : VISIBLE_FIELDS) {
          employeeJson.put(field, childText(employee, field));
        }
        json.add(employeeJson);
      }
    } catch (XPathExpressionException e) {
      log.error("Unable to parse xml", e);
    } catch (IOException e) {
      log.error("Unable to read employees.xml at location: '{}'", d);
    }
    return json;
  }

  /** An employee record is visible to the employee itself and to the managers of that employee. */
  private boolean isVisibleTo(Node employee, String userId) {
    if (userId.equals(childText(employee, "UserID"))) {
      return true;
    }
    NodeList children = employee.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (!"Managers".equals(child.getNodeName())) {
        continue;
      }
      NodeList managers = child.getChildNodes();
      for (int j = 0; j < managers.getLength(); j++) {
        Node manager = managers.item(j);
        if ("Manager".equals(manager.getNodeName())
            && userId.equals(manager.getTextContent().trim())) {
          return true;
        }
      }
    }
    return false;
  }

  private String childText(Node employee, String name) {
    NodeList children = employee.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (name.equals(child.getNodeName())) {
        return child.getTextContent().trim();
      }
    }
    return "";
  }
}
