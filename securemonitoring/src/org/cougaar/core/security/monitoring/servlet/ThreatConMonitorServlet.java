/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 


package org.cougaar.core.security.monitoring.servlet;

// Imported java classes
import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.adaptivity.OperatingMode;

/**
 */
public class ThreatConMonitorServlet
  extends HttpServlet
{
  private SimpleServletSupport support;
  private UnaryPredicate operatingModePredicate;
  private UnaryPredicate conditionPredicate;

  /** Creates new predicate to search for Operating Modes */
  class OperatingModePredicate implements UnaryPredicate
  {
    /** @return true if the object "passes" the predicate */
    public boolean execute(Object o) {
      return (o instanceof OperatingMode);
    }
  }
  /** Creates new predicate to search for Condition */
  class ConditionPredicate implements UnaryPredicate
  {
    /** @return true if the object "passes" the predicate */
    public boolean execute(Object o) {
      return (o instanceof Condition);
    }
  }

  public void setSimpleServletSupport(SimpleServletSupport support) {
    this.support = support;
    operatingModePredicate = new OperatingModePredicate();
    conditionPredicate = new ConditionPredicate();
  }

  public void init(ServletConfig config)
    throws ServletException {
  }

  public void doGet(HttpServletRequest request,
		    HttpServletResponse response)
    throws IOException {
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    out.println("<html>");
    out.println("<head>");
    out.println("<title>ThreatCon Monitor</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>ThreatCon Monitor</H2><BR>");


    out.print("<table border=\"1\" cellpadding=\"10\">");
    out.print("<tr>");
    out.print("<td><b><i>Type</i></b></td>");
    out.print("<td><b><i>Name</i></b></td>");
    out.print("<td><b><i>Value</i></b></td>");
    out.println("</tr>");

    // Query the blackboard
    Collection collection = support.queryBlackboard(conditionPredicate);
    Iterator it = collection.iterator();
    while (it.hasNext()) {
      Condition c = (Condition)it.next();
      processAEobject(out, c);
    }

    // Query the blackboard
    collection = support.queryBlackboard(operatingModePredicate);
    it = collection.iterator();
    while (it.hasNext()) {
      OperatingMode c = (OperatingMode)it.next();
      processAEobject(out, c);
    }

    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private static final String threatConName = 
    "org.cougaar.core.security.monitoring.PERCEIVED_THREAT_LEVEL";

  private void processAEobject(PrintWriter out, Object aeobject) {
    out.print("<tr>");
    String type = "Unexpected type: " + aeobject.getClass().getName();
    String name = "";
    String value = "";
    String bgcolor = "White";

    if (aeobject instanceof Condition) {
      type = "Condition";
      Condition c = (Condition) aeobject;
      name = c.getName();
      value = (c.getValue() != null ? c.getValue().toString() : null);
      if (c.getName().equals(threatConName) ||
	c.getName().equals("org.cougaar.core.security.monitoring.THREATCON_LEVEL")) {
	if ("HIGH".equals(value)) {
	  bgcolor = "#ff6633"; // Red
	}
	else if ("LOW".equals(value)) {
	  bgcolor = "#33ff33"; // Green
	}
	else {
	  bgcolor = "Orange";
	}
      }
    }
    else if (aeobject instanceof OperatingMode) {
      type = "Operating Mode";
      OperatingMode om = (OperatingMode) aeobject;
      name = om.getName();
      value = (om.getValue() != null ? om.getValue().toString() : null);
    }
    
    out.print("<td bgcolor=\"" + bgcolor + "\">" + type + "</td>");
    out.print("<td bgcolor=\"" + bgcolor + "\">" + name + "</td>");
    out.print("<td bgcolor=\"" + bgcolor + "\">" + value + "</td>");
    out.println("</tr>");
  }
}
