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
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.blackboard.OutStandingQuery;
import org.cougaar.core.security.monitoring.blackboard.QueryMapping;
import org.cougaar.core.security.monitoring.plugin.MnRQueryBase;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRResponseViewerComponent
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
  public void setAgentIdentificationService(AgentIdentificationService ais) {
    this.ais = ais;
    if(ais!=null) {
      agentId=ais.getMessageAddress();
    }
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
  public void setLoggingService(LoggingService ls) {
    this.logging=ls;
  }
  
  protected Servlet createServlet() {
    if(ais!=null) {
      agentId = ais.getMessageAddress(); 
    }
    return new QueryResponseViewerServlet();
  }

  public void unload() {
    super.unload();
    // FIXME release the rest!
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

  private class QueryResponseViewerServlet extends HttpServlet {
   
    class QueryRespondRelayPredicate implements  UnaryPredicate{
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof CmrRelay ) {
	  CmrRelay relay = (CmrRelay)o;
	  ret =(relay.getContent() instanceof MRAgentLookUp );
	}
	return ret;
      }
    }
    
    class QueryMappingObjectPredicate implements UnaryPredicate{
      public boolean execute(Object o) {
	boolean ret = false;
	if (o instanceof  QueryMapping ) {
	  return true;
	}
	return ret;
      }
    }
    public void doGet(HttpServletRequest request,
		      HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>MnRQuery Response  Viewer </title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>MRAgentLookUP query Response</H2><BR>");
      out.println("<H3> Monitoring and Response Query and Response  :"+ agentId.toAddress() +"</H3>");
      Collection querresponsecollection=null;
      Collection querymapping=null;
      try {
	blackboard.openTransaction();
	querresponsecollection=blackboard.query(new QueryRespondRelayPredicate());
	querymapping=blackboard.query(new QueryMappingObjectPredicate());
      }
      finally {
	blackboard.closeTransaction();
      }
      if((querresponsecollection==null)||querresponsecollection.isEmpty()) {
	out.println("No Query are currently present ");
	out.flush();
	out.close();
	return;
      }
      Iterator iter=querresponsecollection.iterator();
      CmrRelay relay=null;
      MRAgentLookUpReply reply=null;
      MRAgentLookUp query=null;
      StringBuffer localsb=new StringBuffer();
      StringBuffer remotesb=new StringBuffer();
      localsb.append("<H3> Locally published Queries & Their Response </h3>");
      localsb.append("<table align=\"center\" border=\"2\">\n");
      localsb.append("<TR><TH> Relay ID  </TH><TH> Source </TH><TH>TARGET </TH><TH>SubQuery -- status </TH><TH>QUERY </TH><TH> Response </TH></TR>\n");
      remotesb.append("<H3> Remotly published Queries & Their Response </h3>");
      remotesb.append("<table align=\"center\" border=\"2\">\n");
      remotesb.append("<TR><TH> Relay ID  </TH><TH> Source </TH><TH>TARGET </TH><TH>SubQuery --  status </TH><TH>QUERY </TH><TH> Response </TH></TR>\n");              
      while(iter.hasNext()) {
	relay = (CmrRelay)iter.next();
        UID uid=relay.getUID();
        QueryMapping mapping=MnRQueryBase.findQueryMappingFromBB(uid,querymapping);
	boolean isorginator=MnRQueryBase.isRelayQueryOriginator(uid,querymapping);
        boolean isSubQuery=MnRQueryBase.isRelaySubQuery(uid,querymapping);
        UID originalUID=null;
        if(mapping!=null) {
          if(!isSubQuery) {
            originalUID=mapping.getRelayUID();
            if(logging.isDebugEnabled()) {
              logging.debug(" It it is not sub query then it should be the originator. Either it should have received the query from local components of from upper MnR Managers ");
              if(uid.equals(originalUID)) {
                logging.debug(" relay uid equals relay uid ... Vola this is correct");
              }
              else {
                logging.debug(" relay uid  ! equals relay uid ... Vola this is NOT RIGHT");
              }
            }
            if(relay.getSource().equals(agentId)) {
              localsb.append(convertQueryInfoToHTML(relay,mapping));
            }
            else {
              remotesb.append(convertQueryInfoToHTML(relay,mapping));
            }
          }
        }
        else {
          if(!((relay.getSource().equals(agentId))&&((relay.getTarget()!=null) &&(relay.getTarget().equals(agentId))))) {
            remotesb.append("<TR>Error Cannot find Query Mapping for relay"+uid.toString() +"</TR>\n");
          }
        }
      }
      localsb.append("</table>");
      remotesb.append("</table>");
      out.println(localsb.toString());
      out.println("<BR> <BR>");
      out.println(remotesb.toString()); 
      out.println("</body></html>");
      out.flush();
      out.close();
    }
   
    private String convertQueryInfoToHTML(CmrRelay relay , QueryMapping mapping ) {

      MRAgentLookUpReply reply=null;
      MRAgentLookUp query=null;
      StringBuffer sb =new StringBuffer();
      sb.append("<TR><TD>\n");
      sb.append(relay.getUID().toString());
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      if(relay.getSource()!=null) {
        sb.append(relay.getSource().getAddress());
      }
      else {
        sb.append(" unknown ");
      }
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      if(relay.getTarget()!=null) {
        sb.append(relay.getTarget().getAddress());
      }
      else {
        sb.append(" unknown");
      }
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      if(mapping!=null) {
        ArrayList list=(ArrayList)mapping.getQueryList(); 
        OutStandingQuery outstandingquery;
        if(!list.isEmpty()) {
          sb.append("<ol>"); 
          for(int i=0;i<list.size();i++) {
            outstandingquery=(OutStandingQuery)list.get(i);
            sb.append("<li>Sub Query id:"+ outstandingquery.getUID().toString()+" ---  "+!outstandingquery.isQueryOutStanding()+"</li>\n");
          }
          sb.append("</ol>"); 
        }
        else {
          sb.append(" no sub queries");
        }
      }
      else {
        sb.append(" Error in getting Query Mapping Object");
      }
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      if(relay.getContent()!=null){
        query=(MRAgentLookUp)relay.getContent();
        sb.append(query.toString());
      }
      else {
        sb.append(" Error in getting MRAgentLookUp query ");
      }
      sb.append("</TD>\n");
      sb.append("<TD>\n");
      if(relay.getResponse()!=null){
        reply=(MRAgentLookUpReply)relay.getResponse();
        List list=reply.getAgentList();
        if((list!=null) &&(!list.isEmpty())) {
          sb.append("<ol>");
          ListIterator iter1=list.listIterator();
          MessageAddress agentid=null;
          while(iter1.hasNext()) {
            agentid=(MessageAddress)iter1.next();
            sb.append("<li> "+ agentid.toString()+"</li>\n");
          }
          sb.append("</ol>"); 
        }
        else {
          sb.append("Response is Empty ");
        }
      }
      else {
        sb.append(" No response yet "); 
      }
      sb.append("</TR>\n");
      return sb.toString();
      
    }
    
  }

}
