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
import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.jhuapl.idmef.Classification;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRRegistrationViewerComponent
  extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
  private LoggingService logging;
  private String path;

  public void load() {
    super.load();
  }

  protected String getPath() {
    return path;
  }
  public void setParameter(Object o) {
    List l=(List)o;
    path=(String)l.get(0);
  }

  public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setDomainService(DomainService ds) {
    this.ds = ds;
  }
  
  public void setCommunityService(CommunityService cs) {
    this.cs=cs;
  }

  public void setAgentIdentificationService( AgentIdentificationService agentis){
    if(agentis!=null) {
      this.ais=agentis;
      agentId = ais.getMessageAddress(); 
    }
  }
  
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    if(ais!=null) {
      agentId = ais.getMessageAddress(); 
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  createServlet()called  in MnRRegistrationViewerComponent and ais is null ");
      }
    }
    
    return new RegistrationViewerServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
  }

  public void init(ServletConfig config)
    throws ServletException {
    if(logging.isDebugEnabled()) {
      logging.debug("  init(ServletConfig config)called  in MnRRegistrationViewerComponent");
    }
    ais = (AgentIdentificationService)
      serviceBroker.getService(this, AgentIdentificationService.class, null);
    if(ais!=null) {
      agentId = ais.getMessageAddress();
    }
    else {
      if(logging.isDebugEnabled()) {
        logging.debug("  init() called  in MnRRegistrationViewerComponent and ais is null ");
      }
    }
  }

  public String getBlackboardClientName() {
    return toString();
  }

  // odd BlackboardClient method:
  public long currentTimeMillis() {
    throw new UnsupportedOperationException(
      this+" asked for the current time???");
  }

  // unused BlackboardClient method:
  public boolean triggerEvent(Object event) {
    // if we had Subscriptions we'd need to implement this.
    //
    // see "ComponentPlugin" for details.
    throw new UnsupportedOperationException(
      this+" only supports Blackboard queries, but received "+
      "a \"trigger\" event: "+event);
  }

  private class RegistrationViewerServlet extends HttpServlet {
    class RegistrationPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof CapabilitiesObject ) {
	  return true;
	}
	return ret;
      }
    }
    
    public void doGet(HttpServletRequest request,
		      HttpServletResponse response)
      throws IOException {
      if (ais == null) {
	ais = (AgentIdentificationService)
	  serviceBroker.getService(this, AgentIdentificationService.class, null);
	agentId = ais.getMessageAddress();
      }

      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>MnRRegistration Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>MnRRegistration Viewer</H2><BR>");
      out.println("<H3> Monitoring and Response Capabilities at agent :"
		  + agentId.toAddress() +"</H3>");
      Collection capabilitiesCollection=null;
      try {
	out.println("<H3> Query of the Blackboard started  :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
	blackboard.openTransaction();
	capabilitiesCollection=blackboard.query(new RegistrationPredicate());
	out.println("<H3> Query of the Blackboard Completed   :"
		    + agentId.toAddress() +"</H3>");
	out.flush();
      }
      catch(Exception exp) {
	out.println("<H3> Exception has occured at  :"
		    + agentId.toAddress()+ "Messgae :"
		    + exp.getMessage() +"</H3>");
	out.flush();
      }
      finally {
	blackboard.closeTransaction();
      }
      if((capabilitiesCollection==null)||capabilitiesCollection.isEmpty()) {
	out.println("No Capabilities are currently present ");
	out.flush();
	out.close();
	return;
      }
      if( capabilitiesCollection.size()>1) {
	logging.error("Multiple Capabilities Object on the blackboard:"
		      +agentId.toAddress());
	out.println("Multiple Capabilities Object on the blackboard:"
		    +agentId.toAddress());
	out.flush();
	out.close();
	return;
      }
      Iterator iter=capabilitiesCollection.iterator();
      boolean firstobject=true;
      CapabilitiesObject caps=null;
      while((firstobject)&&(iter.hasNext())) {
	firstobject=false;
	caps=(CapabilitiesObject)iter.next();
      }
      String result=null;
      if(caps!=null) {
	result=createTable(caps);
      }
      out.println( result);
      out.println("</body></html>");
      out.flush();
      out.close();
   

    }

    public String createTable(CapabilitiesObject capabilitiesObject) {
      StringBuffer sb=new StringBuffer();
      sb.append("<table align=\"center\" border=\"2\">\n");
      sb.append("<TR><TH> AnalyzerID </TH><TH> Classification </TH></TR>\n");
      List keyList = Collections.list(capabilitiesObject.keys());
      Collections.sort(keyList);
      String key=null;
      //Classification classification=null;
      RegistrationAlert registartion=null;
      Iterator it = keyList.iterator();
      while(it.hasNext()) {
	key=(String)it.next();
	registartion=(RegistrationAlert)capabilitiesObject.get(key);
	Classification[] classifications=registartion.getClassifications();
	sb.append("<TR><TD>\n");
	sb.append(key);
	sb.append("&nbsp;&nbsp;</TD>\n");
	if(classifications!=null) {
	  sb.append("<TD>\n");
	  sb.append("<UL>");
	  for(int i = 0 ; i < classifications.length ; i++) {
	    sb.append("<LI>"+ classifications[i].getName()+"\n");
	  }
	  sb.append("</UL>\n");
	  sb.append("</TD>\n");
	}
      }
      sb.append("</table>");
      return sb.toString();
    }
  }

}


