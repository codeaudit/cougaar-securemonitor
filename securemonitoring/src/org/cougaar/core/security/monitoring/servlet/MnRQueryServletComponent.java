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
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.servlet.BaseServletComponent;
import org.cougaar.util.UnaryPredicate;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import edu.jhuapl.idmef.Classification;


/**
 *  Use the TraX interface to perform a transformation.
 */
public class MnRQueryServletComponent
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
    this.ais = ais;
    agentId = ais.getMessageAddress(); 
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
    return new QueryServlet();
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

  private class QueryServlet extends HttpServlet {
    class QueryEventPredicate implements UnaryPredicate {
      /** @return true if the object "passes" the predicate */
      public boolean execute(Object o) {
	boolean ret=false; 
	if (o instanceof CmrRelay)  {
	  CmrRelay relay= (CmrRelay)o;
	  ret = (relay.getContent() instanceof MRAgentLookUp );
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
    out.println("<title>MnRQuery</title>");
    out.println("</head>");
    out.println("<body>");
    out.println("<H2>MnRQuery </H2><BR>");
    out.println("<table>");
    out.println("<form action=\"\" method =\"post\">");
    out.println("<tr ><td>Community </td><td>");
    out.println("<TextArea name=community row=1 col=40></TextArea></td></tr>");
    out.println("<tr ><td>Role </td><td>");
    out.println("<TextArea name=role row=1 col=40></TextArea></td></tr>");
    out.println("<tr ><td>ClassificationName </td><td>");
    out.println("<TextArea name=classificationName row=1 col=40></TextArea></td></tr>");
    out.println("<tr ><td>Manager Address </td><td>");
    out.println("<TextArea name=mgraddress row=1 col=40></TextArea></td></tr>");
    out.println("<tr></tr><tr><td><input type=\"submit\">&nbsp;&nbsp;&nbsp;</td>");
    out.println("<td><input type=\"reset\"></td></tr>");
    out.println("</form></table>");
    out.println("</body></html>");
    out.flush();
    out.close();
   

  }
   public void doPost(HttpServletRequest request,
		    HttpServletResponse response)
    throws IOException {
     response.setContentType("text/html");
     PrintWriter out = response.getWriter();
     String classname=null;
     String role=null;
     String community=null;
     String mgrAddress=null;
     classname =(String)request.getParameter("classificationName");
     role=(String)request.getParameter("role");
     community=(String)request.getParameter("community");
     mgrAddress=(String)request.getParameter("mgraddress");
     if((classname==null)&&(role==null)&&(community==null)){
       out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
       out.println("<html>");
       out.println("<head>");
       out.println("<title>MnRQuery</title>");
       out.println("</head>");
       out.println("<body>");
       out.println("<H2>MnRQuery </H2><BR>");
       out.println(" No Classification name  role  community specified :");
       out.println("</body></html>");
       out.flush();
       out.close();
      return;
     }
     out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
     out.println("<html>");
     out.println("<head>");
     out.println("<title>MnRQuery</title>");
     out.println("</head>");
     out.println("<body>");
     out.println("<H2>MnRQuery </H2><BR>");
     out.println(" checking whether community exists :<br>");
     
     CmrFactory factory=(CmrFactory)ds.getFactory("cmr");
     IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
     Classification classification=imessage.createClassification(classname, null );
     MRAgentLookUp agentlookup=new  MRAgentLookUp(null,null,null,null,classification,null,null,true);
     if((community!=null)&& (!community.equals(""))) {
       System.out.println(" setting community to :"+community); 
       agentlookup.community=community;
     }
     else {
       agentlookup.community=null;
     }
     if((role!=null) && (!role.equals(""))) {
       System.out.println("setting role to :"+role);
       agentlookup.role=role;
     }
     else {
       agentlookup.role=null;
     }
     if(mgrAddress!=null) {
       if(mgrAddress.equals("")) {
         out.println("<H2> MAnager  Address is null :</H2>");
       }
     }
     MessageAddress dest_address=MessageAddress.getMessageAddress(mgrAddress);
     CmrRelay relay = factory.newCmrRelay(agentlookup,dest_address);
     try {
       blackboard.openTransaction();
       blackboard.publishAdd(relay);

     } finally {
       blackboard.closeTransactionDontReset();
     }
     boolean atleastone=false;
     out.println("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">");
     out.println("<html>");
     out.println("<head>");
     out.println("<title>MnRQuery</title>");
     out.println("</head>");
     out.println("<body>");
     out.println("<H2>MnRQuery </H2><BR>");
      boolean printed=false;
     while(!atleastone) {
       
       Collection responsecol=null;
       try {
         blackboard.openTransaction();
        responsecol=blackboard.query(new QueryEventPredicate());
       }finally {
         blackboard.closeTransactionDontReset();
       }
       Iterator it = responsecol.iterator();
       MRAgentLookUpReply  reply;
      
       CmrRelay previous=null;
       while(it.hasNext()) {
	 relay=(CmrRelay)it.next();
	 agentlookup=(MRAgentLookUp)relay.getContent() ;
	 if((relay.getSource().equals(agentId)) && (relay.getResponse()!=null)) {
	   atleastone=true;
	   out.println(" Query was" +agentlookup.toString());
	   out.println(" Response is  :");
	   reply=(MRAgentLookUpReply )relay.getResponse();
	   out.println(reply.toString());
	 }
	 else {
	   //out.println("relay receive was :"+relay.toString());
	 }
       }
       out.println("no response yet :");
        out.flush();
     }
     out.flush();
     out.close();
         
   }
  }
}

