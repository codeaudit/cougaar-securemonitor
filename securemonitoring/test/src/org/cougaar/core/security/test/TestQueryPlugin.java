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


package org.cougaar.core.security.test;

// Cougaar core services
//import org.cougaar.core.service.LoggingService;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Iterator;

import edu.jhuapl.idmef.Classification;

/*
class ReadyObjectPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof ReadyObject ) {
      return true;
    }
    return ret;
  }
}
*/
class TestQueryRelayPredicate implements  UnaryPredicate{
 
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ( relay.getContent() instanceof MRAgentLookUp );
    }
    return ret;
  }
}

public class TestQueryPlugin extends ComponentPlugin {
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private IncrementalSubscription testqueryRelays;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private boolean readyflag=false;
  private boolean querypublished=false;
   private Object param;
  
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  public void setParameter(Object o){
    this.param=o;
  }

  public java.util.Collection getParameters() {
    return (Collection)param;
  }
  
  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
    this.communityService=cs;
  }
  
 protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    myAddress = getAgentIdentifier(); 
    testqueryRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new TestQueryRelayPredicate());
    loggingService.debug(" ready false is  true and not published .Going to publish query");
    CmrFactory factory=(CmrFactory)domainService.getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    Classification classification=imessage.createClassification("SecurityException",null );
    /*
      Creates an MRAgentLookUp
    */
    MRAgentLookUp agentlookup=new  MRAgentLookUp("TINY-1AD-Enclave",null,null,null,classification,null,null,true);
    MessageAddress dest_address=getSocietyManager();
    if(dest_address==null) {
      loggingService.debug(" No Society manager to send query to :");
      return;
    }
    CmrRelay relay = factory.newCmrRelay(agentlookup,dest_address);
    loggingService.debug("Going to publish relay :"+ relay.toString());
    getBlackboardService().publishAdd(relay);
        
    
 }
  
  protected void execute() {
    loggingService.debug ("execute of test query called :");
    if(testqueryRelays.hasChanged()) {
      Collection query_col=testqueryRelays.getChangedCollection();
      Iterator iter=query_col.iterator();
      CmrRelay relay=null;
      MRAgentLookUpReply  reply;
      while(iter.hasNext()) {
	relay=(CmrRelay)iter.next();
	  if(relay.getSource().equals(myAddress)) {
	    loggingService.debug(" Got relay as my address :");
	    if(relay.getContent()!=null) {
	      if(relay.getContent() instanceof MRAgentLookUp) {
		if(relay.getResponse()!=null) {
		  reply=(MRAgentLookUpReply )relay.getResponse();
		  loggingService.debug(" Got reply for Query ****************************");
		  loggingService.debug("Query is :"+relay.getContent().toString());
		  loggingService.debug("response is :"+reply.toString()); 
		}
		else {
		  loggingService.debug(" Got NO NO NO ******* reply for Query ****************************");
		  loggingService.debug("Query is :"+relay.getContent().toString());
		}
	      }
	      else {
		loggingService.debug("Relay does not contain MRAgentLookUp");
	      }
	    }
	  }
	  else {
	    loggingService.debug(" I'm not the source of this relay :");
	  }
      }
    }
    
  }
  
  public MessageAddress getSocietyManager() {
    Collection communitycol=null;
    String role="SecurityMnRManager-Society";
    MessageAddress societymgr=null; 
    if(communityService==null) {
      return null;
    }
    /*
      The community service has deprecated the methods used here.

    communitycol=communityService.listAllCommunities();
    Iterator iter=communitycol.iterator();
    String communityname=null;
    Collection agentcol=null;
    while(iter.hasNext()){
      communityname=(String)iter.next();
      agentcol=communityService.searchByRole(communityname,role);
      if(agentcol.isEmpty()) {
	continue;
      }
      else if(agentcol.size()>1) {
	loggingService.debug(" ERROR !!!!! too many society managers ")	;
	return null;
      }
      MessageAddress agent [] =null; 
      agent= (MessageAddress[])agentcol.toArray(new SimpleMessageAddress[1]);
      societymgr=agent[0];
    }
    */
    return societymgr;     
  }
  
}
