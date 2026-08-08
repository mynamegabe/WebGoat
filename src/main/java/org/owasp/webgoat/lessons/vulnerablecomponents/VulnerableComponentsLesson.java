/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import com.thoughtworks.xstream.XStream;
import java.io.StringReader;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

@RestController
@AssignmentHints({"vulnerable.hint"})
public class VulnerableComponentsLesson implements AssignmentEndpoint {

  private static final String ROOT_ELEMENT = "contact";
  private static final List<String> ALLOWED_ELEMENTS =
      List.of("id", "firstName", "lastName", "email");

  @PostMapping("/VulnerableComponents/attack1")
  public @ResponseBody AttackResult completed(@RequestParam String payload) {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    Contact contact = null;

    try {
      if (!StringUtils.isEmpty(payload)) {
        payload =
            payload
                .replace("+", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("> ", ">")
                .replace(" <", "<");
        validateContactDocument(payload);
      }
      contact = (Contact) xstream.fromXML(payload);
    } catch (Exception ex) {
      return failed(this).feedback("vulnerable-components.close").output(ex.getMessage()).build();
    }

    try {
      if (null != contact) {
        contact.getFirstName(); // trigger the example like
        // https://x-stream.github.io/CVE-2013-7285.html
      }
      if (!(contact instanceof ContactImpl)) {
        return success(this).feedback("vulnerable-components.success").build();
      }
    } catch (Exception e) {
      return success(this).feedback("vulnerable-components.success").output(e.getMessage()).build();
    }
    return failed(this).feedback("vulnerable-components.fromXML").feedbackArgs(contact).build();
  }

  /**
   * Only a plain contact document is accepted. The mapping library decides which class to
   * instantiate based on the document itself, so anything it could use to pick another class (type
   * attributes, dynamic proxies, unknown elements, doctype declarations) is rejected before the
   * payload reaches it.
   */
  private void validateContactDocument(String payload) throws Exception {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);

    DocumentBuilder builder = factory.newDocumentBuilder();
    Element root = builder.parse(new InputSource(new StringReader(payload))).getDocumentElement();

    if (root == null || !ROOT_ELEMENT.equals(root.getNodeName()) || root.hasAttributes()) {
      throw new IllegalArgumentException("Only a plain " + ROOT_ELEMENT + " document is accepted");
    }

    NodeList children = root.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      if (child.getNodeType() != Node.ELEMENT_NODE) {
        continue;
      }
      if (!ALLOWED_ELEMENTS.contains(child.getNodeName())
          || child.hasAttributes()
          || hasElementChildren(child)) {
        throw new IllegalArgumentException("Unexpected element: " + child.getNodeName());
      }
    }
  }

  private boolean hasElementChildren(Node node) {
    NodeList children = node.getChildNodes();
    for (int i = 0; i < children.getLength(); i++) {
      if (children.item(i).getNodeType() == Node.ELEMENT_NODE) {
        return true;
      }
    }
    return false;
  }
}
