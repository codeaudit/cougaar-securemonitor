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


package org.cougaar.core.security.monitoring.plugin;

// Cougaar core services
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.multicast.AttributeBasedAddress;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;


public class TestDummySensorPlugin  extends  ComponentPlugin   {
  private LoggingService log;
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private String mgrrole=null;
  private AttributeBasedAddress mgrAddress;
  //private MessageAddress mgrAddress;
  private MessageAddress myAddress;
  private MessageAddress destcluster;
  private String sensor_name="SensorTest";
  private String dest_community=null;
  private Object param;
  private String dest_agent;
  private String _mySecurityCommunity;
    
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
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
    
    log = (LoggingService)
      getBindingSite().getServiceBroker().getService(this,
						     LoggingService.class, null);
    myAddress = getAgentIdentifier();
    log.debug("setupSubscriptions of  called for TestDummySensor Plugin in  :"+ myAddress.toString()); 
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in Test Dummy Sensor  :");
      return;
    }
    requestCommunityServiceInfo();
  }

  private void postSetup() {
    log.debug(" TestDummy sensor My security community :"
	      + _mySecurityCommunity +" agent name :"+myAddress.toString());  
    if(_mySecurityCommunity==null) {
      log.error("No Info about My  SecurityCommunity : returning Cannot continue !"
		+myAddress.toString());  
      return;
    }
    else {
      String myRole=getMyRole(_mySecurityCommunity);
      log.debug(" My Role is  :"+myRole +" agent name :"+myAddress.toString()); 
      if(myRole.equalsIgnoreCase("Member")) {
	mgrrole="SecurityMnRManager-Enclave";
	dest_community=_mySecurityCommunity;
      }
      /*
      else if(myRole.equalsIgnoreCase("SecurityMnRManager-Society")) ) {
	mgrrole="SecurityMnRManager-Enclave";
	dest_community=getDestinationCommunity(myRole);
	if(dest_community==null) {
	  log.error("Cannot get Destination community in agent  !!!!!!"+myAddress.toString()
		    +"\nmy Role is "+ myRole+
		    "\nCannot continue RETURNING !!!!!!!!!!!!!!!");
	  return;
	}
      }
      */
      log.debug(" My destination community is  :"+dest_community
		+ " agent name :"+myAddress.toString());
      mgrAddress=AttributeBasedAddress.
	getAttributeBasedAddress(dest_community,"Role",mgrrole);
      //mgrAddress=MessageAddress.getMessageAddress("Tiny1ADEnclaveSecurityManager");
      log.debug("Created  manager address :"+ mgrAddress.toString());
    }
    
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    TestDummySensor sensor=new TestDummySensor (sensor_name);
    CmrRelay relay=null;
    List capabilities = new ArrayList();
   
    capabilities.add( imessage.createClassification( "POD", null  ) );
    capabilities.add( imessage.createClassification( "TCPSCAN", null  ) );
    capabilities.add( imessage.createClassification( "LOGINFAILURE", null  ) );
    
    ArrayList sources=new ArrayList();
    ArrayList targets=new ArrayList();
    ArrayList addresslist=new ArrayList();
    Address sourceaddress =imessage.createAddress("192.168.1.1",null, Address.IPV4_ADDR);
    addresslist.add(sourceaddress);
    IDMEF_Node node=imessage.createNode("Analyzer",addresslist);
    ArrayList userlist=new ArrayList();
    UserId userid =imessage.createUserId("rtripath");
    userlist.add(userid);
    User user=imessage.createUser(userlist);
    Source source=imessage.createSource(node,user,null,null,null);
    Target target=imessage.createTarget(node,user,null,null,null,null);
    ArrayList ref=new ArrayList();
    ref.add(source.getIdent());
    ref.add(target.getIdent());
    org.cougaar.core.security.monitoring.idmef.Agent agent=imessage.createAgent("Analyzer","testAnalyzer","CA",sourceaddress,ref);
    AdditionalData adddata=imessage.createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agent);

    //creating second source

    Address sourceaddress1 =imessage.createAddress("192.168.1.2",null, Address.IPV4_ADDR);
    ArrayList addresslist1=new ArrayList();
    addresslist1.add(sourceaddress1);
    IDMEF_Node node1=imessage.createNode("Analyzer1",addresslist1);
     ArrayList userlist1=new ArrayList();
    UserId userid1 =imessage.createUserId("rtripath");
    userlist1.add(userid1);
    User user1=imessage.createUser(userlist1);
    Source source1=imessage.createSource(node1,user1,null,null,null);
    Target target1=imessage.createTarget(node1,user1,null,null,null,null);
    ArrayList ref1=new ArrayList();
    ref1.add(source1.getIdent());
    ref1.add(target1.getIdent());
    org.cougaar.core.security.monitoring.idmef.Agent agent1=imessage.createAgent("Analyzer1","testAnalyzer","CA",sourceaddress1,ref1);
    AdditionalData adddata1=imessage.createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agent1);
    sources.add(source);
    sources.add(source1);
    targets.add(target);
    targets.add(target1);
    ArrayList  datas=new ArrayList();
    datas.add(adddata);
    datas.add(adddata1);
    //Classification [] classification=(Classification[])capabilities.toArray(new Classification[0]);
    //Target [] target=new Target[0];
    RegistrationAlert reg=imessage.createRegistrationAlert(sensor,sources,targets,capabilities,datas,IdmefMessageFactory.newregistration,
							    IdmefMessageFactory.SensorType,myAddress.toString());
    /* RegistrationAlert reg=imessage.createRegistrationAlert(sensor,capabilities,
       IdmefMessageFactory.newregistration,
       IdmefMessageFactory.SensorType);
    */
    NewEvent event=factory.newEvent(reg);
    if(log.isDebugEnabled()) {
    log.debug(" going to publish capabilities in Test Dummy sensorplugin  1:");
    log.debug(" going to publish capabilities in TestDummySensorplugin from :"+myAddress.toString()
		       +" Capabilities are :"+reg.toString() );
    }
    //mgrAddress=AttributeBasedAddress.getAttributeBasedAddress(dest_community,"Role",mgrrole);
    if(log.isDebugEnabled())
      log.debug(" destination ABA address is :"+mgrAddress.toString());
    relay = factory.newCmrRelay(event,mgrAddress);
    getBlackboardService().publishAdd(relay);
    if(log.isDebugEnabled()) {
      log.debug("From testDummysensorPlugin :"+ myAddress.toString() +"  relay is :"+relay.toString());
      /*
      log.debug(" Going to dump targets :");
      
      Set stargets =relay.getTargets();
      Iterator iter=stargets.iterator();
      while(iter.hasNext()) {
	log.debug("!!!!!!!!!!!! Target :"+ iter.next().toString());
      }
      */
    }
    ArrayList sources1=new ArrayList();
    ArrayList targets1=new ArrayList();

    ArrayList addresslist2=new ArrayList();
    Address sourceaddress2 =imessage.createAddress("192.168.1.3",null, Address.IPV4_ADDR);
    addresslist2.add(sourceaddress2); 
    IDMEF_Node node2=imessage.createNode("Analyzer2",addresslist2);
     ArrayList userlist2=new ArrayList();
    UserId userid2=imessage.createUserId("rtripath");
    userlist2.add(userid2);
    User user2=imessage.createUser(userlist2);
    Source source2=imessage.createSource(node2,user2,null,null,null);
    Target target2=imessage.createTarget(node2,user2,null,null,null,null);
    sources1.add(source2);
    targets1.add(target2);
    ArrayList ref2=new ArrayList();
    ref2.add(source2.getIdent());
    ref2.add(target2.getIdent());
    org.cougaar.core.security.monitoring.idmef.Agent agent2=imessage.createAgent("Analyzer2","testAnalyzer","CA",sourceaddress2,ref2);
    AdditionalData adddata2=imessage.createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agent2);
    ArrayList addresslist3=new ArrayList();
    Address sourceaddress3 =imessage.createAddress("192.168.1.1",null, Address.IPV4_ADDR);
    addresslist3.add(sourceaddress3);
    IDMEF_Node node3=imessage.createNode("Analyzer",addresslist3);
    ArrayList userlist3=new ArrayList();
    UserId userid3 =imessage.createUserId("rtripath");
    userlist3.add(userid3);
    User user3=imessage.createUser(userlist3);
    Source source3=imessage.createSource(node3,user3,null,null,null);
    Target target3=imessage.createTarget(node3,user3,null,null,null,null);
    ArrayList ref3=new ArrayList();
    ref3.add(source3.getIdent());
    ref3.add(target3.getIdent());
    org.cougaar.core.security.monitoring.idmef.Agent agent3=imessage.createAgent("Analyzer3","testAnalyzer","CA",sourceaddress3,ref3);
    AdditionalData adddata3=imessage.createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agent3);
     sources1.add(source3);
     targets1.add(target3);
    ArrayList datas1=new ArrayList();
    datas1.add(adddata2);
    datas1.add(adddata3);
    sensor=new TestDummySensor (sensor_name+1);
    capabilities.add( imessage.createClassification( "SecurityException", null  ) );
    capabilities.add( imessage.createClassification( "JarException", null  ) );
    //classification=(Classification[])capabilities.toArray(new Classification[0]);
    
    RegistrationAlert reg1=imessage.createRegistrationAlert(sensor,sources1,targets1,capabilities,datas1,IdmefMessageFactory.newregistration,
							   IdmefMessageFactory.SensorType,myAddress.toString());
    /*reg=imessage.createRegistrationAlert(sensor,capabilities,IdmefMessageFactory.newregistration,
					 IdmefMessageFactory.SensorType);
    */
    Event event1=factory.newEvent(reg1);
    
    CmrRelay relay1 = factory.newCmrRelay(event1,mgrAddress);
    if(log.isDebugEnabled())
      log.debug("From testDummysensorPlugin with new Sensor  :"+ myAddress.toString() +"  relay is :"+relay1.toString());
    //getBlackboardService().openTransaction();
    getBlackboardService().publishAdd(relay1);
    log.debug("Publish DONE  ****************************************");
    //getBlackboardService().closeTransaction();
    //mgrAddress=AttributeBasedAddress.getAttributeBasedAddress(dest_community,"Role",mgrrole);
   
  }
          
       
  protected void execute () {
    // process unallocated tasks
  }
  
  private void requestCommunityServiceInfo() {
    if(communityService==null) {
     log.error(" Community Service is null" +myAddress.toString()); 
    }
    CommunityResponseListener crl = new CommunityResponseListener() {
	public void getResponse(CommunityResponse resp) {
	  Object response = resp.getContent();
	  if (!(response instanceof Set)) {
	    String errorString = "Unexpected community response class:"
	      + response.getClass().getName() + " - Should be a Set";
	    log.error(errorString);
	    throw new RuntimeException(errorString);
	  }
          configureCommunity((Set) response);
	}
      };

    // Request security community.
    String filter="(CommunityType=" +
      CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ")";
    Collection communities =
      communityService.searchCommunity(null, filter, false, Community.COMMUNITIES_ONLY, crl);
    if (communities != null) {
      configureCommunity((Set)communities);
    }
  }
 
  private void configureCommunity(Set communities) {
    if (communities.size() > 1) {
      log.warn("This agent belongs to more than one security community");
    }
    else {
      Iterator it = communities.iterator();
      while (it.hasNext()) {
        Community community = (Community) it.next();
        _mySecurityCommunity = community.getName();
        postSetup();
        break;
      }
    }
  }
 
  private String getMyRole(String mySecurityCommunity) {
    String myRole=null;
    boolean enclavemgr=false;
    boolean societymgr=false;
    boolean member=false;
    if(communityService==null) {
      log.error(" Community Service is null" +myAddress.toString()); 
    }
    Collection roles = null;
    // communityService.getEntityRoles(mySecurityCommunity,myAddress.toString());
    Iterator iter=roles.iterator();
    String role;
    while(iter.hasNext()) {
      role=(String)iter.next();
      log.debug(" Roles for agent :"+ myAddress.toString() +"community :"+ mySecurityCommunity+
		"role :"+role);
      if(role.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
	enclavemgr=true;
      }
      else if(role.equalsIgnoreCase("SecurityMnRManager-Society")) {
	societymgr=true;
      }
      else if(role.equalsIgnoreCase("Member")) {
	member=true;
      }
    }
    if(member){
      myRole="Member";
    }
    else if(enclavemgr) {
      myRole="SecurityMnRManager-Enclave"; 
    }
    else if(societymgr) {
      myRole="SecurityMnRManager-Society";
    }
    log.debug(" returning !!!!! role :"+myRole);
    return myRole;
    						      
  }
  
  public String getDestinationCommunity(String role) {
    if(communityService==null) {
      log.error(" Community Service is null" +myAddress.toString()); 
    }
    String destrole=null;
    if(role.equalsIgnoreCase("member")) {
      destrole="SecurityMnRManager-Enclave";
    }
    else if(role.equalsIgnoreCase("SecurityMnRManager-Enclave")) {
      destrole="SecurityMnRManager-Society";
    }
    String filter="(CommunityType=" + 
      CommunityServiceUtil.SECURITY_COMMUNITY_TYPE + ")";
    Collection securitycol= null; //communityService.search(filter);
    Iterator itersecurity=securitycol.iterator();
    String comm=null;
    while(itersecurity.hasNext()) {
      comm=(String)itersecurity.next();
      Collection societysearchresult= null;//communityService.searchByRole(comm,destrole);
      if(societysearchresult.isEmpty()) {
	continue;
      }
      else {
	if(societysearchresult.size()>1) {
	   log.error(" Too many Society Manager " +myAddress.toString());
	   return null;
	}
	break;
      }
    }
    return comm;
  }
  
  
}
