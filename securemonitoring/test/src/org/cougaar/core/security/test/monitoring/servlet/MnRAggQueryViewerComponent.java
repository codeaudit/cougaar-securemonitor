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


package org.cougaar.core.security.test.monitoring.servlet;

// Imported java classes
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.DetailsDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRAggQueryViewerComponent
  extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
  //private NamingService ns;
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
    if(ais!=null) {
      this.ais = ais;
      agentId = ais.getMessageAddress(); 
    }
  }

   public void setBlackboardService(BlackboardService blackboard) {
    this.blackboard = blackboard;
  }

  public void setDomainService(DomainService ds) {
    this.ds = ds;
  }
  
   public void setCommunityService(CommunityService cs) {
     System.out.println(" set community services call for Servlet component :");
     this.cs=cs;
   }
  /*
  public void setNamingService(NamingService ns) {
     System.out.println(" set  Naming services call for Servlet component :");
     this.ns=ns;
  }
  */

  protected Servlet createServlet() {
    
    if(ais==null) {
      ais = (AgentIdentificationService)
          serviceBroker.getService(this, AgentIdentificationService.class,
                                   null);
      
    }
    if(ais!=null) {
       agentId = ais.getMessageAddress();
    }
    return new AggQueryServlet();
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

  private class AggQueryServlet extends HttpServlet {
    class AggQueryEventPredicate implements UnaryPredicate {
      private MessageAddress targetAgent;
      public AggQueryEventPredicate(MessageAddress agent) {
        targetAgent=agent;
      }
      /** @return true if the object "passes" the predicate */

      public boolean execute(Object o) {
	boolean ret=false; 
	if (o instanceof CmrRelay)  {
	  CmrRelay relay= (CmrRelay)o;
          if((!relay.getSource().equals(targetAgent)) &&
             ((relay.getContent() instanceof DetailsDrillDownQuery )||
              (relay.getContent() instanceof DrillDownQuery))){
            return true;
          }
        }
        return ret;
      }
    }
    
    public void doGet(HttpServletRequest request,
		    HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      if (ais == null) {
        ais = (AgentIdentificationService)
          serviceBroker.getService(this, AgentIdentificationService.class,
                                   null);
        agentId = ais.getMessageAddress();
      }
      PrintWriter out = response.getWriter();
      Collection aggQueryCol=null;
      out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
      out.println("<html>");
      out.println("<head>");
      out.println("<title>MnRAggQuery</title>");
      out.println("</head>");
      out.println("<body>");
      out.println("<H2>MnRAggQuery Viewer  </H2><BR>");
      if(agentId==null){
        out.println("<H3> Cannot get address of this agent :</H3>" );
        out.flush();
        out.close();
        return ;
      } 
      
      out.println("<table>");
      out.println("<TH> Query </TH>");
      try {
        blackboard.openTransaction();
        aggQueryCol=blackboard.query(new AggQueryEventPredicate(agentId));
      } finally {
        blackboard.closeTransactionDontReset();
      }
      if(aggQueryCol.size()>0) {
        out.println("<table border= \"2\">");
        out.println("<TR><TH> Query </TH> <TH> Originator UID </TH> <TH>Source</TH> <TR>");
        Iterator iter= aggQueryCol.iterator();
        CmrRelay relay=null;
        DrillDownQuery drilldownquery=null;
        DetailsDrillDownQuery detailsdrilldownquery=null;
        while(iter.hasNext()){
          relay= (CmrRelay)iter.next();
          if(relay.getContent()instanceof DrillDownQuery){
            drilldownquery =(DrillDownQuery)relay.getContent();
            out.println("<TR BGCOLOR = \"#ff99ff\" Color=\"#f0f8ff\">");
            out.println("<td>"+drilldownquery.getAggQuery()+"</td>");
            out.println("<td>"+drilldownquery.getOriginatorsUID()+"</td>");
            out.println("<td>"+relay.getSource()+"</td>"); 
            out.println("</TR>");
          }
          else if(relay.getContent()instanceof DetailsDrillDownQuery) {
            detailsdrilldownquery =(DetailsDrillDownQuery)relay.getContent(); 
            out.println("<TR BGCOLOR = \"#6699ff\" Color=\"#f0f8ff\">");
            out.println("<td> ----- </td>");
            out.println("<td>"+detailsdrilldownquery.getOriginatorUID()+"</td>");
            out.println("<td>"+relay.getSource()+"</td>"); 
            out.println("</TR>");
          }
        }
        out.println("</table>");
      }
      else {
        out.println("<H3>No Agg Query present <H3>");
        
      }
      out.println("</body></html>");
      out.flush();
      out.close();
    }
    
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      
    }
  }
  
   

}

