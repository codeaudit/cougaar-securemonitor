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
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.servlet.SimpleServletSupport;
import org.cougaar.util.ConfigFinder;
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

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.CreateTime;
import edu.jhuapl.idmef.Heartbeat;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLUtils;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

/**
 *  Use the TraX interface to perform a transformation.
 */
public class EventViewerServlet
  extends HttpServlet
{
  private SimpleServletSupport support;
  private ConfigFinder confFinder;

   /** Creates new predicate to search for Events */
  class IdmefEventPredicate implements UnaryPredicate
  {
    /** @return true if the object "passes" the predicate */
    public boolean execute(Object o) {
      if (o instanceof Event)  {
	Event event= (Event)o;
	IDMEF_Message msg = event.getEvent();
	return true;
      }
      return false;
    }
  }

  public void setSimpleServletSupport(SimpleServletSupport support) {
    this.support = support;
    confFinder = ConfigFinder.getInstance();
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
    out.println("<title>IDMEF Events</title>");
    out.println("</head>");
    out.println("<body>");

    // Query the blackboard
    Collection collection = support.queryBlackboard(new IdmefEventPredicate());
   
    out.println("<H2>IDMEF Events (" + collection.size() + " events found) </H2><BR>");
    Iterator it = collection.iterator();
    String document = null;

    out.print("<table border=\"1\" cellpadding=\"10\">");
    out.print("<tr>");
    out.print("<td><b><i>Alert ID</i></b></td>");
    out.print("<td><b><i>Create Time</i></b></td>");
    out.print("<td><b><i>Classification</i></b></td>");
    out.print("<td><b><i>Assessment</i></b></td>");
    out.print("<td><b><i>Analyzer</i></b></td>");
    out.print("<td><b><i>Source</i></b></td>");
    out.print("<td><b><i>Target</i></b></td>");
    out.print("<td><b><i>Additional Data</i></b></td>");
    out.print("</tr>");

    if (!it.hasNext()) {
      out.print("No Event available");
    }

    while (it.hasNext()) {
      IDMEF_Message msg = ((Event)it.next()).getEvent();
      document = msg.toString();
      //System.out.println("IDMEF message:\n" + document);
      processMessage(out, msg);
    }
    out.println("</body></html>");
    out.flush();
    out.close();
  }

  private void processMessage(PrintWriter out, IDMEF_Message msg) {
    out.print("<tr>");
    String value = null;

    if (msg instanceof Alert) {
      // Alert
      Alert alert = (Alert) msg;
      // Identifier
      out.print("<td>" + alert.getIdent() + "</td>");

      // Creation Time
      CreateTime createTime = alert.getCreateTime();
      value = (createTime != null) ? createTime.getidmefDate() : "";
      out.print("<td>" + value + "</td>");

      // Classification
      Classification[] classifications = alert.getClassifications();
      out.print("<td>");
      if (classifications != null) {
	for (int i = 0 ; i < classifications.length ; i++) {
	  out.print("[" + i + "] Origin:" + classifications[i].getOrigin() + "<br>");
	  out.print("   Name:" + classifications[i].getName() + "<br>");
	}
      }
      out.print("</td>");

      // Assessment
      Assessment assessement = alert.getAssessment();
      value = (assessement != null) ? assessement.toString() : "";
      out.print("<td>" + value + "</td>");

      // Analyzer
      Analyzer analyzer = alert.getAnalyzer();
      out.print("<td>");
      if (analyzer != null) {
	out.print("Analyzer ID:" + analyzer.getAnalyzerid() + "<br>");
      }
      out.print("</td>");

      // Sources
      out.print("<td>");
      Source[] sources = alert.getSources();
      if ( sources!= null) {
	for (int i = 0 ; i < sources.length ; i++) {
	  out.print("[" + i + "]");
	  IDMEF_Node n = sources[i].getNode();
	  printNode(out, n);
	  out.print("<br>");
	}
      }
      out.print("</td>");

      // Targets
      out.print("<td>");
      Target[] targets = alert.getTargets();
       if (targets != null) {
	for (int i = 0 ; i < targets.length ; i++) {
	  out.print("[" + i + "]");
	  IDMEF_Node n = targets[i].getNode();
	  printNode(out, n);
	  out.print("<br>");
	}
      }
     out.print("</td>");

      // Additional Data
      AdditionalData[] additionalData = alert.getAdditionalData();
      outputAdditionalData(out, additionalData);
    }
    // Heatbeat
    else if (msg instanceof Heartbeat) {
      Heartbeat heartbeat = (Heartbeat) msg;

      // Identifier
      out.print("<td>" + heartbeat.getIdent() + "</td>");

      // Creation Time
      CreateTime createTime = heartbeat.getCreateTime();
      value = (createTime != null) ? createTime.getidmefDate() : "";
      out.print("<td>" + value + "</td>");

      out.print("<td></td> <td></td>");

      // Analyzer
      Analyzer analyzer = heartbeat.getAnalyzer();
      out.print("<td>");
      if (analyzer != null) {
	out.print("Analyzer ID:" + analyzer.getAnalyzerid() + "<br>");
      }
      out.print("</td>");

      // Additional Data
      AdditionalData[] additionalData = heartbeat.getAdditionalData();
      outputAdditionalData(out, additionalData);
    }
    else {
      out.print("Unknow Event");
    }
    out.print("</tr>");
  }

  private void outputAdditionalData(PrintWriter out,
                        AdditionalData[] additionalData) {
    StringBuffer value = new StringBuffer();
    if (additionalData != null) {
      for(int i = 0 ; i < additionalData.length ; i++) {
        if (additionalData[i] != null) {
          value.append( additionalData[i].getType() + "/" +
                         additionalData[i].getMeaning());
          if (!AdditionalData.XML.equals(additionalData[i].getType())) {
             value.append("/" + additionalData[i].getAdditionalData() + "<br/>");
          } else {
            try {
               DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
               DocumentBuilder builder = factory.newDocumentBuilder();
               Document document = builder.newDocument();
               Node node=additionalData[i].getXMLData().convertToXML(document);
               document.appendChild(node);
               value.append(XMLUtils.doc2String(document));
            }
            catch (Exception e) {
              value .append("Unable to retrieve XML data: " + e);
              e.printStackTrace(out);
            }
          }
        }
      }
    }
    out.print("<td>" + value.toString() + "</td>");
  }

  private void printNode(PrintWriter out, IDMEF_Node n) {
    if (n != null) {
      out.print("Ident:" + n.getIdent() + "<br>");
      out.print("Name:" + n.getName() + "<br>");
      out.print("Category:" + n.getCategory() + "<br>");
      out.print("Location:" + n.getLocation() + "<br>");

      Address[] addresses = n.getAddresses();
      if ( addresses != null) {
        for (int i = 0 ; i < addresses.length ; i++) {
          out.print("Address[" + i + "]/" + addresses[i].getCategory()
		  + " = " + addresses[i].getAddress());
        }
      }
    }
    else {
      out.print("Node is null");
    }
  }
}
