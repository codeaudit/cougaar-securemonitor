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
import org.cougaar.core.security.monitoring.blackboard.AggregatedResponse;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DetailsDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRAggResponseViewerComponent
extends BaseServletComponent implements BlackboardClient  {
  private MessageAddress agentId;
  private AgentIdentificationService ais;
  private BlackboardService blackboard;
  private DomainService ds;
  private CommunityService cs;
 
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
    if(this.ais!=null) {
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
    //System.out.println(" set community services call for Servlet component :");
    this.cs=cs;
  }
   
  protected Servlet createServlet() {
    return new DetailsDrillDownViewerServlet();
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

  private class DetailsDrillDownViewerServlet extends HttpServlet {

      
    public void doGet(HttpServletRequest request,
                      HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
       String uri=request.getRequestURI();
      Collection drilldownquery=null;
      try {
        blackboard.openTransaction();
        drilldownquery=blackboard.query(new DrillDownPredicate(agentId));
      }finally {
        blackboard.closeTransactionDontReset();
      }
      out.println(CreateHeader());
      String page=CreatePage(drilldownquery,uri);
      out.println(page);
      out.println(CreateTail());
      out.flush();
      out.close();
   

    }
    public void doPost(HttpServletRequest request,
                       HttpServletResponse response)
      throws IOException {
      response.setContentType("text/html");
      PrintWriter out = response.getWriter();
      String uri=request.getRequestURI();
      out.println(CreateHeader());
      String targetagent=null;
      String parentUID=null;
      String originatorUID=null;
      String topublish=null;
      targetagent=request.getParameter("targetAgent");
      originatorUID=request.getParameter("originatorsUID");
      parentUID=request.getParameter("parentsUID");
      topublish=request.getParameter("publishdetailsQuery");
      if(targetagent==null || parentUID==null || originatorUID==null || topublish==null){
        out.println(" Cannot publish Details Drill Down request as targetagent/ parentUID/originatorUID is NUll");
        out.flush();
      }
      
      if(topublish.equalsIgnoreCase("true") ){
        CmrFactory factory=(CmrFactory)ds.getFactory("cmr");
        CmrRelay relay=null;
        
        try {
          blackboard.openTransaction();
          relay=factory.newCmrRelay(new DetailsDrillDownQuery(UID.toUID(originatorUID.trim()),UID.toUID(parentUID.trim())),
                                    MessageAddress.getMessageAddress(targetagent));
          out.println(" publishing request for Detail Events to ---> " +targetagent );
          blackboard.publishAdd(relay);
          
        }
        catch (Exception exp) {
           out.println(" Cannot publish Details Drill Down request " + exp.getMessage());
           out.flush();
        }
        finally {
          blackboard.closeTransactionDontReset();
        }   
        out.println("<H3> Successfully  publishing request for Detail Events to agent "+ targetagent +"</h3>");
        
        out.flush();
      }
      else if( topublish.equalsIgnoreCase("false")) {
        out.println("<H3> Got request to show details for agent "+ targetagent +"</h3>");
        out.println(processDetailsResponse(targetagent,originatorUID,parentUID,uri));
      }
      out.println("<table>");
      out.println("<tr> <form name=\""+originatorUID+"\"");
      out.println("action =\""+uri +"\"" +" method=\"post\" onSubmit =\"submitme(this)\">"  );
      out.println("<input type=\"hidden\" name=\"targetAgent\" value=\""
                   + targetagent+"\">");
      out.println("<input type=\"hidden\" name=\"originatorsUID\" value=\""
                  +originatorUID+ "\">");
      out.println("<input type=\"hidden\" name=\"parentsUID\" value=\""
                  +parentUID+ "\"> ");
      out.println("<input type=\"hidden\" name=\"publishdetailsQuery\" value=\"false\">");
      out.println("<input type=\"Submit\" value=\"Refresh \"></form>");
      out.println("</tr></table>");
      out.println(CreateTail());
      out.flush();
      out.close();
    }
    
  }

  public String processDetailsResponse(String targetagent , String originatorUID, String parentUID, String uri) {
    StringBuffer buff=new StringBuffer();
    Collection detailsDrillDownQuery=null;
    try {
      blackboard.openTransaction();
      detailsDrillDownQuery=blackboard.query(new DetailsDrillDownQueryPredicate
                                             ( MessageAddress.getMessageAddress(targetagent),
                                              UID.toUID(originatorUID.trim())));
    }
    catch (Exception exp) {
      buff.append(exp.getMessage()); 
      return buff.toString();
    }
    finally {
      blackboard.closeTransactionDontReset();
    }
    buff.append(CreatePage(detailsDrillDownQuery,uri));
    return buff.toString();
    
  }

  public String CreateHeader () {
    StringBuffer buf =new StringBuffer();
    buf.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
    buf.append("<html>");
    buf.append("<head>");
    buf.append("<title>MnR Details Drill Down Response Viewer </title>");
    buf.append("<script language=\"javascript\">");
    buf.append("function submitme(form)");
    buf.append("{ form.submit()}</script>");
    buf.append("</head>");
    buf.append("<body>");
    return  buf.toString();
  }

  public String CreateTail () {
    StringBuffer buf =new StringBuffer();
    buf.append("</body>");
    buf.append("</html>");
    return  buf.toString();
  }

  public String  CreatePage( Collection Drillcol, String uri) {
    StringBuffer buf =new StringBuffer();
    buf.append("<H2>MnR Agg Details  Down Response Viewer </H2><BR>");
    if(Drillcol==null ){
      buf.append(" No Deatils Drill Down Response present for : "+ agentId);
      return buf.toString();
    }
    if(Drillcol.isEmpty()) {
      buf.append(" No Drill Down query present for : "+ agentId);
      return buf.toString();
    }
    buf.append(" <br>  <br>  <br>");
    Iterator iter =Drillcol.iterator();
    CmrRelay relay=null;
    DrillDownQuery query=null;
    AggregatedResponse response=null;
    int ctr0=0;
    while(iter.hasNext()){
      relay=(CmrRelay)iter.next();
      if(relay.getContent()==null) {
        buf.append(" <h4>Contents of relay is NULL " + relay.getUID().toString()+"</h4>");
      }
      if(relay.getResponse()!=null) {
        buf.append(" <h4>Response for relay with UID " + relay.getUID().toString()+"</h4>");
        buf.append("<table border=\"3\" >");
        buf.append("<tr><th> Event Type </th> <th> Source </th><th> Request to Show Deatils</th></tr>");
        response=(AggregatedResponse)relay.getResponse();
        Iterator i1=response.getEvents();
        ConsolidatedEvent cevents=null;
        Event event=null;
        int ctr1=0;
        while(i1.hasNext()) {
          Object o=i1.next();
          if(o instanceof Event) {
            event=(Event)o;
            buf.append("<TR BGCOLOR = \"#6699ff\" Color=\"#f0f8ff\">");
            buf.append("<td> Event </td>");
            buf.append("<td>"+event.getSource()+"</td>");
            buf.append("<td> --</td>");
            buf.append("</TR>");
          }
          else if(o instanceof ConsolidatedEvent) {
            cevents=(ConsolidatedEvent)o;
            buf.append("<tr  BGCOLOR = \"#ff99ff\" Color=\"#f0f8ff\" >");
            buf.append("<td> ConsolidatedEvent </td>");
            buf.append("<td>"+cevents.getSource()+"</td>");
            buf.append("<td>");
            if(isDetailsQueryPublished(cevents)) {
              buf.append("<form name=\""+cevents.getOriginatorUID()+cevents.getSource()+"\"");
              buf.append("action =\""+uri +"\"" +" method=\"post\" onSubmit =\"submitme(this)\" target=\"_blank\">" );
              buf.append("<input type=\"hidden\" name=\"targetAgent\" value=\""
                          + cevents.getSource().toString()+"\">");
              buf.append("<input type=\"hidden\" name=\"originatorsUID\" value=\""
                          +cevents.getOriginatorUID().toString() + "\">");
              buf.append("<input type=\"hidden\" name=\"parentsUID\" value=\""
                          +cevents.getParentUID().toString() + "\"> ");
              buf.append("<input type=\"hidden\" name=\"publishdetailsQuery\" value=\"false\">");
              buf.append("<input type=\"Submit\" value=\"SHOW Details \"></form>"); 
            }
            else {
              buf.append("<form name=\""+cevents.getOriginatorUID()+cevents.getSource()+"\"");
              buf.append("action =\""+uri +"\"" +" method=\"post\" onSubmit =\"submitme(this)\"target=\"_blank\" >" );
              buf.append("<input type=\"hidden\" name=\"targetAgent\" value=\""
                          + cevents.getSource().toString()+"\">");
              buf.append("<input type=\"hidden\" name=\"originatorsUID\" value=\""
                          +cevents.getOriginatorUID().toString() + "\">");
              buf.append("<input type=\"hidden\" name=\"parentsUID\" value=\""
                          +cevents.getParentUID().toString() + "\"> ");
              buf.append("<input type=\"hidden\" name=\"publishdetailsQuery\" value=\"true\">");
              buf.append("<input type=\"Submit\" value=\"Publish Details Event Request \"></form>");
              
            }
            buf.append("</td>");
            buf.append("</TR>");
            
          }
        }
        buf.append("</table>");
      }
    }
    return buf.toString();
    
  }

  public boolean isDetailsQueryPublished(ConsolidatedEvent cevents) {
    boolean published=false;
    if(cevents==null){
      return published;
    }
    Collection detailsDrillDownQuery=null;
    try {
      blackboard.openTransaction();
      detailsDrillDownQuery=blackboard.query(new DetailsDrillDownQueryPredicate
                                             (cevents.getSource(),
                                              cevents.getOriginatorUID()));
    }
    catch (Exception exp) {
      //buff.append(exp.getMessage()); 
       published=false;
    }
    finally {
      blackboard.closeTransactionDontReset();
    }
    if(detailsDrillDownQuery.size()>0) {
      published=true; 
    }
    return published;
  }
 
  class DrillDownPredicate implements UnaryPredicate{
    private MessageAddress  myAddress;
    public DrillDownPredicate(MessageAddress agent) {
      myAddress=agent;
    }
    public boolean execute(Object o) {
      boolean ret = false;
      CmrRelay cmrRelay=null;
      if (o instanceof CmrRelay ) {
        cmrRelay=(CmrRelay)o;
        if((cmrRelay.getSource().equals(myAddress))&&
           (cmrRelay.getContent() instanceof DrillDownQuery) &&
           (cmrRelay.getResponse() instanceof AggregatedResponse  )){
          return true;
        }
      }
      return ret;
    }
  }
  
  class DetailsDrillDownQueryPredicate implements UnaryPredicate{
    private MessageAddress targetAgent;
    private UID originatorUID;
    
    public DetailsDrillDownQueryPredicate(MessageAddress agent, UID originatorsUID) {
      targetAgent=agent;
      originatorUID=originatorsUID;
    }
    public boolean execute(Object o) {
      boolean ret = false;
      CmrRelay cmrRelay=null;
      DetailsDrillDownQuery detailsquery=null;
      if (o instanceof CmrRelay ) {
        cmrRelay=(CmrRelay)o;
        if((cmrRelay.getTarget().equals(targetAgent))&&
           (cmrRelay.getContent() instanceof DetailsDrillDownQuery)){
          detailsquery=(DetailsDrillDownQuery)cmrRelay.getContent();
          if(detailsquery.getOriginatorUID().equals(originatorUID)){
            return true;
          }
        }
      }
      return ret;
    }
  }
  
 
}
