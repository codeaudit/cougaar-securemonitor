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
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.OutStandingQuery;
import org.cougaar.core.security.monitoring.blackboard.QueryMapping;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;

class CapabilitiesObjectPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}

public abstract class MnRQueryBase extends ComponentPlugin {
  protected DomainService domainService;
  protected CommunityService communityService;
  protected LoggingService loggingService;
  protected CommunityServiceUtil _csu;
  protected MessageAddress myAddress;
 
  private boolean _isRoot;
  private boolean _rootReady;
 
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService ds) {
    domainService = ds;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  /**
   * Used by the binding utility through reflection to set my CommunityService
   */
  public void setCommunityService(CommunityService cs) {
    communityService = cs;
  }

  /**
   * Used by the binding utility through reflection to get my CommunityService
   */
  public CommunityService getCommunityService() {
    return communityService;
  }
  
  public void setLoggingService(LoggingService ls) {
    loggingService = ls; 
  }
  
  public LoggingService getLoggingService() {
    return loggingService; 
  }
  
  protected void setupSubscriptions() {
    if (myAddress == null) {
      myAddress = getAgentIdentifier();
      if(loggingService == null) {
        loggingService = (LoggingService)
          getServiceBroker().getService(this, LoggingService.class, null); 
      }
      _csu = new CommunityServiceUtil(getServiceBroker());

      _csu.amIRoot(new RootListener());
    }
  }

  protected boolean amIRoot() {
    return _isRoot;
  } 

  protected boolean isRootReady() {
    return _rootReady;
  } 
  
/*
  protected Community getMySecurityCommunity() {   
  Community mySecurityCommunity= _csu.getSecurityCommunity(myAddress.toString());
  if(mySecurityCommunity==null) {
  loggingService.warn(" Canot get my role as Manager in any Security Community :"+myAddress.toString() );
  }
  return mySecurityCommunity;
  }
*/
  
  /**
   * @param query
   * @param caps
   * @param sensors - true when the search is performed on the local sensors.
   *                  false when the search is performed on the subordinate managers.
   */
  protected void findAgent(final MRAgentLookUp query, 
                           final CapabilitiesObject caps, 
                           final boolean sensors, 
                           final FindAgentCallback callback) {
  
    if(query==null) {
      loggingService.error("Query was null in findAgent. Sensor type :"+sensors);
      callback.execute(Collections.EMPTY_LIST);
      return;
    }
    if(caps==null) {
      loggingService.error("Capabilities was null returning");
      callback.execute(Collections.EMPTY_LIST);
      return;
    }
    if(loggingService.isDebugEnabled()){
      if(sensors){
        loggingService.debug("Looking for Local Sensors");
      }
      else {
        loggingService.debug("Looking for Managers");
      }
    }
    
    //printhash(caps);
    String community=query.community;
    String role=query.role;
    if(loggingService.isDebugEnabled()){
      loggingService.debug("Query receive in  findAgent is :"+ query.toString());
    }

    if (community != null) {
      CommunityServiceUtilListener listener = 
        new CommunityServiceUtilListener() {
          public void getResponse(Set agents) {
            if(loggingService.isDebugEnabled()) {
              loggingService.debug(" Response received in callback for community search "+ agents.size());
              loggingService.debug("Calling finishFindAgent:");
            }
            agents= agentsAsString(new HashSet(agents));
            finishFindAgent(query, caps, sensors, agents, callback);
          }
        };
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Searching with community (" +
                             community + ") and role (" +
                             role + ")");
      }
      if (role != null) {
        searchByCommunityAndRole(community, role, listener);
      } else {
        searchByCommunity(community, listener); 
      }
    } else if (role!=null)  {
      loggingService.error("Cannot search by role only. " + 
                           "A community name must be provided.");
      callback.execute(Collections.EMPTY_LIST);
    } else {
      finishFindAgent(query, caps, sensors, Collections.EMPTY_LIST, callback);
    }
  }
  public Set agentsAsString(Set agents){
    Set agentName=new HashSet();
    if(!agents.isEmpty()) {
      Iterator iter=agents.iterator();
      while(iter.hasNext()){
        agentName.add(((Object)iter.next()).toString());
      }
    }
    return agentName;
  }

  private void finishFindAgent(MRAgentLookUp query, CapabilitiesObject caps, 
                               boolean sensors, Collection commagents,
                               FindAgentCallback callback) {
    Enumeration keys=caps.keys();
    Classification queryClassification=query.classification;
    Source querySource=query.source;
    Target queryTarget=query.target;
    String sourceOfAttack=query.source_agent;
    String targetOfAttack=query.target_agent;
    String community=query.community;
    String role=query.role;

    List classagents;
    List sourceagents;
    List targetagents;
    List sourceofAttackAgents;
    List targetofAttackAgents;
    Collection commonAgents=null;
    if(loggingService.isDebugEnabled()) {
      loggingService.debug("Size of result after community and role search is  " +commagents.size() );
    }
    classagents=searchByClassification(queryClassification,caps,sensors);
    if(loggingService.isDebugEnabled()) {
      loggingService.debug("Size of result with classification is " +classagents.size() );
      loggingService.debug("Result with classification is "+ classagents);
    }
    
   
    sourceagents=searchBySource(querySource,caps,sensors);
    // loggingService.debug("Size of result with source  is :" +sourceagents.size() );
   
    targetagents=searchByTarget(queryTarget,caps,sensors);
    // loggingService.debug("Size of result with target is :" +targetagents.size() );
    
    //loggingService.debug("Size of result with target is :" +targetagents.size() );
    sourceofAttackAgents=searchBySourceOfAttack(sourceOfAttack,caps,sensors);
    //loggingService.debug("Size of result with source of ATTACK  is :" +sourceofAttackAgents.size() );
   
    targetofAttackAgents=searchByTargetOfAttack(targetOfAttack,caps,sensors);
    // loggingService.debug("Size of result with target of ATTACK  is :" +targetofAttackAgents.size() );
    
    if (((community!=null) || (role!=null))&& (commagents.isEmpty())) {
      loggingService.debug(" Community Rol combination is empty :");
      commonAgents=Collections.EMPTY_LIST;
    } else {
      boolean iscomagentset=false;
      if((community!=null) || (role!=null)) {
        iscomagentset=true;
      }
      //if(queryClassification!=null) {
      //loggingService.debug("Query for classification was not null:");
      if(!iscomagentset) {
        commonAgents=classagents;
        iscomagentset=true;
      }
      else {
        commonAgents=findCommanAgents(commagents,classagents);
        if(loggingService.isDebugEnabled()) {
          loggingService.debug("Size of resultafter combining classification and commagents is  " +commonAgents.size() );
          loggingService.debug("Result with classification is "+ classagents);
        }
      }
      if(!iscomagentset) {
        commonAgents=sourceagents;
        iscomagentset=true;
      }
      else{
        commonAgents=findCommanAgents(commonAgents,sourceagents);
      }
      if(!iscomagentset) {
        commonAgents=targetagents;
        iscomagentset=true;
      }
      else {
        commonAgents=findCommanAgents(commonAgents,targetagents);
      }
      if(!iscomagentset) {
        commonAgents=sourceofAttackAgents;
        iscomagentset=true;
      }
      else {
        commonAgents=findCommanAgents(commonAgents,sourceofAttackAgents);
      }
      if(!iscomagentset) {
        commonAgents=targetofAttackAgents;
        iscomagentset=true;
      }
      else {
        commonAgents=findCommanAgents(commonAgents,targetofAttackAgents);
      }
    }
    if(loggingService.isDebugEnabled()) {
      loggingService.debug("Printing result of query:" + sensors);
      Iterator iter=commonAgents.iterator();
      while(iter.hasNext()){
        loggingService.debug("agent is :"+(String)iter.next());  
      }
    }
    callback.execute(commonAgents);
    
  }
  
  
  private Collection findCommanAgents(Collection list1, Collection list2) {
    HashSet common = new HashSet(list1);
    /*
      if(loggingService.isDebugEnabled()) {
      //loggingService.debug(" Agents before findCommanAgents in list 1 is :"+ list1);
      Iterator iter=common.iterator();
      if(iter.hasNext()){
      //loggingService.debug(" Trying to find out if elements in first list is string:"+(String)iter.next());
      }
      //loggingService.debug(" Agents before findCommanAgents in list 2 is :"+ list1);
      }
    */
    common.retainAll(list2);
    return common;
  }
  
  private List searchByClassification(Classification searchClassification,CapabilitiesObject caps, boolean sensors) {
   
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    ArrayList agentlist=new ArrayList();
    /*if(searchClassification==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      if(searchClassification!=null){
        loggingService.debug("In find agent FUNCTION  query is :"+searchClassification.getName()+
                             "Origin  "+searchClassification.getOrigin() );
      }
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug("In capabilities object : Key is "+ key  );
      }
      Classification [] classifications=reg.getClassifications();
      if(classifications==null) {
        return agentlist;
      }
      if(searchClassification==null) {
        //loggingService.debug("got search classification as null will return all sensors :");
        if(sensors) {
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //  loggingService.debug("Analyzer id is :"+ reg.getAgentName());
            //loggingService.debug("Adding sensor key when classification is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when classification is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when classification is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(isClassificationPresent(searchClassification,classifications)) {
        //loggingService.debug("Got calssification equal:" + key);
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug("Analyzer id is :"+ reg.getAgentName());
            //loggingService.debug("Adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key :"+key);
            agentlist.add(key);
          }
        }
      }
    }
    return agentlist;
  }
  
  private List searchBySource(Source searchSource,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source [] sources=null;
    ArrayList agentlist=new ArrayList();
    /*
      if(searchSource==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug("In  searchBySources FUNCTION  query is :"+searchSource);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      if(searchSource==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when query source is null :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when query source is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  managerwhen query source is null :");
          if(reg.getType().equals( IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("adding security manager  key when query source is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(sources==null) {
        return agentlist;
      }
      if(isSourceORTargetPresent(searchSource,sources)) {
        //loggingService.debug("Got source equal:" + reg.getType());
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("adding security manager  key :"+key);
            agentlist.add(key);
          }
	  
        }
      }
    }
    return agentlist;
    
  }
  
  private List searchByTarget(Target searchTarget,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets=null;
    ArrayList agentlist=new ArrayList();
    /*if(searchTarget==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchByTargets FUNCTION  query is :"+searchTarget);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      if(searchTarget==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when query target is null:");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when query target is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when query target is null:");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when query target is null :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(targets==null) {
        return agentlist;
      } 
      if(isSourceORTargetPresent(searchTarget,targets)) {
        //loggingService.debug(" Got source equal:" + reg.getType());
        if(sensors) {
          //loggingService.debug("Looking for sensors agents :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key :"+key);
            agentlist.add(key);
          }
	  
        }
      }
    }
    return agentlist;
  }
  
  private List searchBySourceOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Source []sources =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchBySourcesofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      sources=reg.getSources();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when source of attack is null  :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when source of attack is null:"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  managerwhen source of attack is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug(" adding security manager  keywhen source of attack is null  :"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(sources==null) {
        return agentlist;
      }
      if(additionaldatas==null) {
        return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
        data=additionaldatas[i];
        org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
        if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
          if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
            agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          }
        }
        if(agentinfo!=null) {
          if(agentname.trim().equals(agentinfo.getName())) {
            String [] ref=agentinfo.getRefIdents();
            if(ref!=null) {
              String refstring=null;
              boolean found=true;
              for(int x=0;x<ref.length;x++) {
                refstring=ref[x];
                for(int z=0;z<sources.length;z++) {
                  if(refstring.trim().equals(sources[z].getIdent().trim())) {
                    found=true;
                    break;
                  }
                }
                if(found)
                  break;
              }
              if(found) {
                if(sensors) {
                  //    loggingService.debug("Looking for sensors agents :");
                  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
                    //loggingService.debug(" adding sensor key :"+key);
                    agentlist.add(reg.getAgentName());
                  }
                }
                else {
                  //loggingService.debug("Looking for Security  manager :");
                  if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
                    //loggingService.debug(" adding security manager  key :"+key);
                    agentlist.add(key);
                  }
                }
		
              }
            }
          }
        }
      }
    }
    return agentlist;
  }
  
  private List searchByTargetOfAttack(String agentname,CapabilitiesObject caps, boolean sensors) {
    String key=null;
    Enumeration keys=caps.keys();
    RegistrationAlert reg;
    Target [] targets =null;
    AdditionalData [] additionaldatas=null;
    AdditionalData data=null;
    ArrayList agentlist=new ArrayList();
    /*if(agentname==null) {
      return agentlist;
      }
    */
    if (loggingService.isDebugEnabled()) {
      //loggingService.debug(" in  searchByTargetofattack  FUNCTION  query is :"+agentname);
    }
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      reg= (RegistrationAlert)caps.get(key);
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" in capabilities object : Key is "+ key );
      }
      targets=reg.getTargets();
      additionaldatas=reg.getAdditionalData();
      if(agentname==null) {
        if(sensors) {
          //loggingService.debug("Looking for sensors agents when target of attack is null  :");
          if((reg.getType().equals(IdmefMessageFactory.SensorType))){
            //loggingService.debug(" adding sensor key when target of attack is null :"+key);
            agentlist.add(reg.getAgentName());
          }
        }
        else {
          //loggingService.debug("Looking for Security  manager when target of attack is null :");
          if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
            //loggingService.debug("Adding security manager  key when target of attack is null:"+key);
            agentlist.add(key);
          }
        }
        continue;
      }
      if(targets==null) {
        return agentlist;
      }
      if(additionaldatas==null) {
        return agentlist;
      }
      for(int i=0;i<additionaldatas.length;i++) {
        data=additionaldatas[i];
        org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
        if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
          if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
            agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          }
        }
        if(agentinfo!=null) {
          if(agentname.trim().equals(agentinfo.getName())) {
            String [] ref=agentinfo.getRefIdents();
            if(ref!=null) {
              String refstring=null;
              boolean found=true;
              for(int x=0;x<ref.length;x++) {
                refstring=ref[x];
                for(int z=0;z<targets.length;z++) {
                  if(refstring.trim().equals(targets[z].getIdent().trim())) {
                    found=true;
                    break;
                  }
                }
                if(found)
                  break;
              }
              if(found) {
                if(sensors) {
                  //loggingService.debug("Looking for sensors agents :");
                  if((reg.getType().equals(IdmefMessageFactory.SensorType))){
                    //loggingService.debug(" adding sensor key :"+key);
                    agentlist.add(reg.getAgentName());
                  }
                }
                else {
                  // loggingService.debug("Looking for Security  manager :");
                  if(reg.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
                    //loggingService.debug("Adding security manager  key :"+key);
                    agentlist.add(key);
                  }
                }
		
              }
            }
          }
        }
      }
    }
    return agentlist;
    // return new ArrayList();
  }

  private class Status {
    public Object value;
  }

  protected void searchByCommunity (String community,
                                    CommunityServiceUtilListener callback) {
    searchByCommunityAndRole(community, CommunityServiceUtil.MEMBER_ROLE,
                             callback);
  }

  protected void searchByCommunityAndRole(String community, String role,
                                          CommunityServiceUtilListener csul) {
    if (communityService==null) {
      loggingService.error("Community Service is null in " + 
                           "searchByCommunityAndRole " + myAddress); 
      csul.getResponse(Collections.EMPTY_SET);
    } else if (community==null) {
      loggingService.error("community is null in searchByCommunityAndRole " +
                           myAddress); 
      csul.getResponse(Collections.EMPTY_SET);
    } if (role==null) {
      loggingService.error("Role is null in searchByCommunityAndRole " +
                           myAddress); 
      csul.getResponse(Collections.EMPTY_SET);
    } else {
      _csu.getAgents(community, role, csul);
    }
  }
  
  protected boolean areClassificationsEqual(Classification existingclassification,Classification newclassification) {
    boolean equal=false;
    if((existingclassification.getOrigin().trim().equalsIgnoreCase(newclassification.getOrigin().trim()))
       &&(existingclassification.getName().trim().equalsIgnoreCase(newclassification.getName().trim()))) {
      // loggingService.debug(" returning true  :");
      return true;
    }   
    return equal;
  }
  
  protected boolean isClassificationPresent(Classification queryclassification,Classification[] classificationList) {
    Classification currentclassification;
    boolean isclassification=false;
    for(int i=0;i<classificationList.length;i++) {
      currentclassification=classificationList[i];
      /*loggingService.debug("current classification :"+ classificationtoString(currentclassification));
        loggingService.debug("query classification :"+ classificationtoString(queryclassification));
      */
      if(areClassificationsEqual(currentclassification,queryclassification)){
        isclassification=true;
        return isclassification;
      }
    }
    return isclassification  ;
  }
  
  protected boolean isSourceORTargetPresent(Object inquery,Object[] inObjectArray) {
    boolean ispresent=false;
    //loggingService.debug("Size of source or target is :"+ inObjectArray.length);
    for(int i=0;i<inObjectArray.length;i++) {
      if(areSourceORTargetEqual(inObjectArray[i],inquery)){
        ispresent=true;
        return ispresent;
      }
      else {
        //  loggingService.debug(" source or Target is not present :");
      }
    }
    return ispresent ;
  }
  
  protected boolean areSourceORTargetEqual(Object existing , Object inquery) {
    boolean equal=false;
    boolean nodeequal=false;
    boolean userequal=false;
    boolean serviceequal=false;
    boolean processequal=false;
    if(!(((existing instanceof Source) && (inquery instanceof Source))||
         ((existing instanceof Target) && (inquery instanceof Target)))) {
      return equal;
    }
    IDMEF_Node existingNode=null;
    IDMEF_Node queryNode=null;
    User existingUser=null;
    User queryUser=null;
    Service existingService=null;
    Service queryService=null;
    IDMEF_Process existingProcess=null;
    IDMEF_Process queryProcess=null;
    if((existing instanceof Source) && (inquery instanceof Source)) {
      Source existingSource=(Source)existing;
      Source inquerySource=(Source)inquery;
      existingNode=existingSource.getNode();
      queryNode=inquerySource.getNode();
      existingUser=existingSource.getUser();
      queryUser=inquerySource.getUser();
      existingService=existingSource.getService();
      queryService=inquerySource.getService();
      existingProcess=existingSource.getProcess();
      queryProcess=inquerySource.getProcess();
    }
    if((existing instanceof Target) && (inquery instanceof Target)) {
      Target existingTarget=(Target)existing;
      Target inqueryTarget=(Target)inquery;
      existingNode=existingTarget.getNode();
      queryNode=inqueryTarget.getNode();
      existingUser=existingTarget.getUser();
      queryUser=inqueryTarget.getUser();
      existingService=existingTarget.getService();
      queryService=inqueryTarget.getService();
      existingProcess=existingTarget.getProcess();
      queryProcess=inqueryTarget.getProcess();
      
    } 
    if((existingNode!=null)&&(queryNode!=null)){
      boolean nameequal=false;
      boolean addressequal=false;
      boolean categoryequal=false;
      String queryname=queryNode.getName();
      String existingname=existingNode.getName();
      Address queryAddress []=queryNode.getAddresses();
      Address existingAddress[]=existingNode.getAddresses();
      String queryCategory=queryNode.getCategory();
      String existingCategory=existingNode.getCategory();
      if(queryname==null) {
        nameequal=true;
        //loggingService.debug("In Idmef node queryname was null:");	
      }
      if((queryname!=null)&&(existingname!=null)) {
        if(queryname.trim().equals(existingname.trim())) {
          //loggingService.debug("In Idmef node queryname are equal:");
          nameequal=true;
        }
      }
      if(queryAddress==null) {
        addressequal=true;
        //loggingService.debug("In Idmef node queryAddress was null:");
      }
      if((queryAddress!=null)&&(existingAddress!=null)) {
        loggingService.debug("In Idmef queryAddress && existing address is not  null:");
        if(existingAddress.length>=queryAddress.length) {
          Address inqueryAddress=null;
          for(int i=0;i<queryAddress.length;i++) {
            inqueryAddress=queryAddress[i];
            if(!containsAddress(inqueryAddress,existingAddress)) {
              addressequal=false;
              break;
            }
          }
          addressequal=true;
          //loggingService.debug("In Idmef node address are equal :");
        }
	
      }
      if(queryCategory==null) {
        //loggingService.debug("In Idmef node queryCategory was null:");
        categoryequal=true;
      }
      if((queryCategory !=null) && (existingCategory!=null)) {
        //loggingService.debug("query category is :"+ queryCategory);
        //loggingService.debug("existing Category category is :"+ existingCategory);
        if(queryCategory.trim().equals(existingCategory.trim())) {
          loggingService.debug("In Idmef node queryCategory are equal :");
          categoryequal=true;
        }
      }
      if(existingCategory==null){
        //loggingService.debug("existing Category category is NULL :");
      }
      
      if( nameequal &&  addressequal && categoryequal) {
        //loggingService.debug("In Idmef node are equal :");
        nodeequal=true;
      }
      
    }
    else if((existingNode==null)&&(queryNode==null)){
      nodeequal=true;
      //loggingService.debug("In Idmef node are equal :");
    }
    else if(queryNode==null) {
      nodeequal=true;
    }
          
    if((existingUser!=null)&&(queryUser!=null)){
      UserId [] queryUserId=queryUser.getUserIds();
      UserId [] existingUserId=existingUser.getUserIds();
      if(queryUserId==null) {
        //loggingService.debug("In Idmef query User  is null  :");
        userequal =true;
      }
      if((queryUserId !=null) &&(existingUserId!=null)) {
        if(existingUserId.length>=queryUserId.length) {
          UserId userid=null;
          for(int i=0;i<queryUserId.length;i++) {
            userid=queryUserId[i];
            if(!containsUserId(userid,queryUserId)) {
              userequal=false;
              break;
            }
          }
          userequal=true;
          //loggingService.debug("In Idmef query User  is true  :");
        }
      }
    }
    else if((existingUser==null)&&(queryUser==null)){
      //loggingService.debug("In Idmef query User  is true  :");
      userequal=true;
    }
    else if(queryUser==null){
      userequal=true;
    }
    
    if((existingService!=null)&&(queryService!=null)){
      String existingServiceName=existingService.getName();
      String queryServiceName=queryService.getName();
      Integer existingPort=existingService.getPort();
      Integer queryPort=queryService.getPort();
      String existingPortList=existingService.getPortlist();
      String queryPortList=queryService.getPortlist();
      String existingProtocol=existingService.getProtocol();
      String queryprotocol=queryService.getProtocol();
      boolean nameequal=false;
      boolean portequal=false;
      boolean portlistequal=false;
      boolean protocolequal=false;
      if(queryServiceName==null) {
        nameequal=true;
      }
      if((existingServiceName!=null) && (queryServiceName!=null)) {
        if(existingServiceName.trim().equals(queryServiceName.trim())) {
          nameequal=true;
        }
      }
      if(queryPort==null) {
        portequal=true;
      }
      if((existingPort!=null) &&(queryPort!=null)) {
        if(existingPort.intValue()==queryPort.intValue()) {
          portequal=true;
        }
      }
      if(queryPortList==null) {
        portlistequal =true;
      }
      if((existingPortList!=null)&&(queryPortList!=null)) {
        if(existingPortList.trim().equals(queryPortList.trim())) {
          portlistequal=true;
        }
      }
      if(queryprotocol==null) {
        protocolequal=true;
      }
      if((existingProtocol!=null) &&(queryprotocol!=null)) {
        if(existingProtocol.trim().equals(queryprotocol.trim())) {
          protocolequal=true;
        }
      }
	
      if( nameequal &&  portequal &&  portlistequal &&  protocolequal) {
        serviceequal=true;
        //loggingService.debug("In Idmef serviceequal  is true  :");
      }
    }
    else if((existingService==null)&&(queryService==null)){
      //loggingService.debug("In Idmef serviceequal  is true  :");
      serviceequal=true;
    }
    else if(queryService==null) {
      serviceequal=true;
    }
    
    if((existingProcess!=null)&&(queryProcess!=null)){
      String existingPath=existingProcess.getPath();
      String queryPath=queryProcess.getPath();
      String existingName=existingProcess.getName();
      String queryName=queryProcess.getName();
      boolean processNameequal=false;
      boolean processPathequal=false;
      if(queryPath==null) {
        processPathequal=true;
      }
      if((existingPath!=null) &&(queryPath!=null)) {
        if(existingPath.trim().equals(queryPath.trim())) {
          processPathequal=true;
        }
      }
      if(queryName==null) {
        processNameequal=true;
      }
      if((existingName!=null) &&(queryName!=null)) {
        if(existingName.trim().equals(queryName.trim())) {
          processNameequal=true;
        }
      }
      if(processPathequal && processNameequal) {
        processequal=true;
        //loggingService.debug("In Idmef processequal  true :");
      }
    }
    else if((existingProcess==null)&&(queryProcess==null)){
      //loggingService.debug("In Idmef processequal  true :");
      processequal=true;
    }
    else if(queryProcess==null) {
      processequal=true;
    }
    if( nodeequal &&  userequal &&  serviceequal &&  processequal) {
      loggingService.debug("Either source or target is equal  :");
      equal=true;
    }
    return equal;
     
  }
 
  protected boolean containsUserId(UserId inUserId, UserId [] arrayUserId) {
    boolean contains=false;
    UserId userid;
    if(inUserId==null) {
      return contains;
    }
    boolean nameequal=false;
    boolean numberequal=false;
    if(arrayUserId!=null) {
      for(int i=0;i<arrayUserId.length;i++) {
        userid=arrayUserId[i];
        String inName=inUserId.getName();
        String name=userid.getName();
        Integer innumber=inUserId.getNumber();
        Integer number=userid.getNumber();
        if((inName!=null)&& (name!=null)) {
          if(inName.trim().equals(name.trim())) {
            nameequal=true;
          }
        }
        if((innumber!=null)&&(number!=null)) {
          if(innumber.intValue()==number.intValue()) {
            numberequal=true;
          }
        }
        if(nameequal && numberequal) {
          contains=true;
          return contains;
        }
	    
      }
    }
    return contains;
  }
    
  protected boolean containsAddress(Address anAddress, Address [] arrayAddress) {
    boolean contains=false;
    Address address;
    if(anAddress==null) {
      return contains;
    }
    if(arrayAddress!=null) {
      //myAddresses=this.getAddresses();
      for(int i=0;i<arrayAddress.length;i++) {
        address=arrayAddress[i];
        String stringaddress=address.getAddress();
        String inaddress=anAddress.getAddress();
        String category=address.getCategory();
        String incategory=anAddress.getCategory();
        boolean addressequal=false;
        boolean categoryequal=false;
        if((stringaddress!=null)&& (inaddress!=null)) {
          if(stringaddress.trim().equals(inaddress.trim())) {
            addressequal=true;
          }
        }
        else if((stringaddress==null)&& (inaddress==null)) {
          addressequal=true;
        }
        if((category!=null)&&(incategory!=null))  {
          if(category.trim().equals(incategory.trim())) {
            categoryequal=true;
          }
        }
        else if((category==null)&&(incategory==null))  {
          categoryequal=true;
        }
        if(addressequal && categoryequal) {
          contains=true;
          return contains;
        }
      }
    }
    return contains;
  }
  
  public static  boolean isRelayQueryOriginator(UID givenUID, Collection queryMappingCol ) {
    boolean isoriginator=false;
    QueryMapping querymapping=null;
    if(!queryMappingCol.isEmpty()){
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        querymapping=(QueryMapping)iter.next();
        if(querymapping.getRelayUID().equals(givenUID)) {
          isoriginator=true;
          return isoriginator;
        }
      }
    }
    return isoriginator;
  }
  
  public static boolean isRelaySubQuery(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;
    boolean issubquery=false;
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        foundqMapping=(QueryMapping)iter.next();
        relayList=foundqMapping.getQueryList();
        if(relayList==null) {
          return false;
        }
        for(int i=0;i<relayList.size();i++) {
          outstandingq=(OutStandingQuery)relayList.get(i);
          if(outstandingq.getUID().equals(givenUID)) {
            issubquery=true;
            return issubquery;
          }
        }
      }
    } 
    else {
      return issubquery;
    }
    return issubquery;
  }
  
  public static QueryMapping findQueryMappingFromBB(UID givenUID, Collection queryMappingCol ) {
    QueryMapping foundqMapping=null;
    ArrayList relayList;
    OutStandingQuery outstandingq;  
    //QueryMapping tempqMapping;
    if(!queryMappingCol.isEmpty()){
      
      Iterator iter=queryMappingCol.iterator();
      while(iter.hasNext()) {
        foundqMapping=(QueryMapping)iter.next();
        if(foundqMapping.getRelayUID().equals(givenUID)) {
          return foundqMapping;
        }
        relayList=foundqMapping.getQueryList();
        if(relayList==null) {
          continue;
        }
        for(int i=0;i<relayList.size();i++) {
          outstandingq=(OutStandingQuery)relayList.get(i);
          if(outstandingq.getUID().equals(givenUID)) {
            return foundqMapping;
          }
        }
      }
      
    }
    else {
      return null;
    }
    return null;
  }
  
  protected void printhash(CapabilitiesObject cap) {
    Enumeration keys=cap.keys();
    String key=null;
    RegistrationAlert registration=null;
    loggingService.debug(" CAPABILITIES OBJECT IN ADDRESS :"+myAddress.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
      }
      registration=(RegistrationAlert)cap.get(key);
      loggingService.debug(" data of  alert is :"+registration.toString());
    }
  }

  public CmrRelay findCmrRelay(UID key) {
    CmrRelay relay = null;
    final UID fKey = key;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof CmrRelay) {
            CmrRelay relay = (CmrRelay)o;
            return ((relay.getUID().equals(fKey)) &&(relay.getContent() instanceof MRAgentLookUp));
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" size for query of relay with MRAgentLookUp and relay id "+key.toString()+"size :"+ relays.size());  
      }
      relay = (CmrRelay)relays.iterator().next();
    }
    return relay;
  } 

  private class RootListener 
  implements Runnable, CommunityServiceUtilListener {
    public void getResponse(Set entities) {
      _isRoot = !(entities == null || entities.isEmpty());
      _rootReady = true;
      loggingService.info("The agent " + myAddress + " is root? " + _isRoot);
      ThreadService ts = (ThreadService)
        getServiceBroker().getService(this, ThreadService.class, null);
      ts.getThread(this, this).schedule(0);
      getServiceBroker().releaseService(this, ThreadService.class, ts);
    }

    public void run() {
      getBlackboardService().openTransaction();
      try {
        execute();
      } finally {
        getBlackboardService().closeTransaction();
      }
    }
  }

  public interface FindAgentCallback {
    void execute(Collection agents);
  }
}
