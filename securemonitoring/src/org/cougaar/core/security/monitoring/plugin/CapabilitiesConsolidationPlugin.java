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


import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NotificationObject;
import org.cougaar.core.security.monitoring.blackboard.MnRManagerObject;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

class ModifiedCapabilitiesPredicate implements UnaryPredicate{
  LoggingService log=null;
  public ModifiedCapabilitiesPredicate(LoggingService ls) {
    log=ls;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      //log.debug("Capabilities Object True :");
      return true;
    }
    return ret;
  }
}

class ConsolidatedCapabilitiesRelayPredicate implements UnaryPredicate{
  LoggingService log=null;
  public ConsolidatedCapabilitiesRelayPredicate(LoggingService ls) {
    log=ls;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      if(relay.getContent() instanceof Event) {
        Event event = (Event)relay.getContent();
        ret = (event.getEvent() instanceof AgentRegistration);
      }
      else {
        if (log.isDebugEnabled()) {
          // log.debug(" ConsolidatedCapabilitiesRelayPredicate:" + ret);
        }
        return ret;
      }
    }
    if (log.isDebugEnabled()) {
      //log.debug(" ConsolidatedCapabilitiesRelayPredicate:" + ret);
    }
    return ret;
  }
}


class AgentRegistrationPredicate implements UnaryPredicate{
  LoggingService log=null;
  public AgentRegistrationPredicate(LoggingService ls) {
    log=ls;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof AgentRegistration){
        // log.debug(" AgentRegistrationPredicate: True" );	
        return true;
      }
    }
    return ret;
  }
}


/**
 *
 **/
public class CapabilitiesConsolidationPlugin extends ComponentPlugin {

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private IncrementalSubscription modifiedcapabilities;
  private IncrementalSubscription capabilitiesRelays;
  private IncrementalSubscription agentRegistrations;
  private IncrementalSubscription notification;

//  private Community mySecurityCommunity=null;
  
  private MessageAddress myAddress;
  private MessageAddress _managerAddress;
  
  /** Holds value of property loggingService. */
  private LoggingService loggingService;
  private boolean readcollection=false;
  private long _pollInterval=10 * 1000;
  Object mylock=new Object();
  
  private CommunityServiceUtil _csu;
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
  
  public void setCommunityService(CommunityService cs) {
    this.communityService=cs;
  }
   
  /**
   * subscribe to tasks and programming assets
   */
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this,LoggingService.class, null);

    myAddress = getAgentIdentifier();
    _csu = new CommunityServiceUtil(getServiceBroker());
//    mySecurityCommunity = getMySecurityCommunity();

    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of CapabilitiesConsolidationPlugin called for "
                           + myAddress.toAddress());
      loggingService.debug("Using CommunityServiceUtil for getSecurityCommunity:");
    }
    MnRManagerObject mgrObject=new MnRManagerObject(myAddress);
    getBlackboardService().publishAdd(mgrObject);
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("Mgr Object is published");
    }
    _csu.amIRoot(new RegistrationListener());
        
    modifiedcapabilities= (IncrementalSubscription)getBlackboardService().subscribe(new ModifiedCapabilitiesPredicate(loggingService));
    capabilitiesRelays= (IncrementalSubscription)getBlackboardService().subscribe(new ConsolidatedCapabilitiesRelayPredicate(loggingService));
    agentRegistrations= (IncrementalSubscription)getBlackboardService().subscribe(new AgentRegistrationPredicate(loggingService));
  }
  

  public void setManagerAddress(final MessageAddress mgrAddress) {
    loggingService.debug(" setManagerAddress called with : "+ mgrAddress + " in agent :" +myAddress);
    if(_managerAddress==null) {
      Runnable task = new Runnable() {
          public void run (){
            _managerAddress = mgrAddress;
            loggingService.debug("Found security manager('" + _managerAddress + "') for manager('" + myAddress + "')");
            getBlackboardService().openTransaction();
            if(loggingService.isDebugEnabled()){
              loggingService.debug("Publishing notification object :");
            }
            getBlackboardService().publishAdd(new NotificationObject());
            getBlackboardService().closeTransaction(); 
          }
        };
      ThreadService ts = (ThreadService)
        getServiceBroker().getService(this, ThreadService.class, null);
      ts.getThread(this, task).schedule(0);
      getServiceBroker().releaseService(this, ThreadService.class, ts);
    }
    else {
      loggingService.debug("Mgr addres is not null in agent  : "+ myAddress +" Mgr address : "+_managerAddress);
    }
  }

  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
    
    updateRelayedCapabilities();
    // Unwrap subordinate capabilities from new/changed/deleted relays
    loggingService.debug("Update of relay called from :"+myAddress.toAddress());
   
    if(_managerAddress == null) {
      return; 
    }
     
    if (loggingService.isDebugEnabled())
      loggingService.debug(" Execute of CapabilitiesConsolidation Plugin called"
                           +myAddress.toAddress() );
    DomainService service=getDomainService();
    if(service==null) {
      if (loggingService.isDebugEnabled()) 
        loggingService.debug(" Got service as null in CapabilitiesConsolidation Plugin :"+ myAddress.toAddress());
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    //Event event=null;
    IdmefMessageFactory idmeffactory=factory.getIdmefMessageFactory();
    Collection  modifiedcapabilities_col=modifiedcapabilities.getChangedCollection();
    if(!readcollection) {
      if(( modifiedcapabilities_col==null)||( modifiedcapabilities_col.size()==0)){
        modifiedcapabilities_col=modifiedcapabilities.getCollection();
        readcollection=true;
      }
	 
    }
    
    if(( modifiedcapabilities_col==null)||( modifiedcapabilities_col.size()==0)){
      if (loggingService.isDebugEnabled()) 
        loggingService.debug(" No modified capabilities currently present" +
                             "RETURNING !");
      return;
    }
    
    if(modifiedcapabilities_col.size()>1) {
      if (loggingService.isDebugEnabled())
        loggingService.debug(" Error Multiple complete capabilities object on blackboard in Capabilities"+
                             " Consolidation plugin !!!!!!!!!!!!!!!!!!!"+
                             " CONFUSION CONFUSION CONFUSION  RETURNIG !!!!!!!:"+myAddress.toAddress() );
      return;
    }
   
    ConsolidatedCapabilities consCapabilities=null;
    CapabilitiesObject capabilitiesobject=null;
    Iterator iter= modifiedcapabilities_col.iterator();
    if(iter.hasNext()) {
      capabilitiesobject=(CapabilitiesObject )iter.next();
    }
    
    //printhash(capabilitiesobject);
    consCapabilities=createConsolidatedCapabilities();
    RegistrationAlert registration=null;
    Classification consclassifications[]=consCapabilities.getClassifications();
    Classification regclassifications[]=null;
    Source consSources[]=consCapabilities.getSources();
    Source regSources[]=null;
    Target consTargets[]=consCapabilities.getTargets();
    Target regTargets[]=null;
    AdditionalData consAddData[]=consCapabilities.getAdditionalData();
    AdditionalData regAddData[]=null;
    Enumeration keys=capabilitiesobject.keys();
    String key=null;
    
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      if (loggingService.isDebugEnabled())
        loggingService.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
      if(consSources!=null)
        loggingService.debug("Consolidated source length is :"+consSources.length);
      if(consAddData!=null)
        loggingService.debug("Consolidated Additional data length is :"+consAddData.length);
      registration=(RegistrationAlert)capabilitiesobject.get(key);
      regclassifications=registration.getClassifications();
      regAddData=registration.getAdditionalData();
      regSources=registration.getSources();
      regTargets=registration.getTargets();
      if(regSources!=null)
        loggingService.debug("Reg source length is :"+regSources.length);
      if(regAddData!=null)
        loggingService.debug("Reg  Additional data length is :"+regAddData.length);
      if(regAddData==null) {
        loggingService.debug("Additional data is NOT NULL in Reg alert:"); 
      }
	
      if(consclassifications==null){
        //log.debug("consclassifications was null Creating one :"); 
        consclassifications=new Classification[regclassifications.length];
        System.arraycopy(regclassifications,0,consclassifications,0,regclassifications.length);
        //printConsolidation(consclassifications,"First Classification[] is added to consolidate Classification");
      }
      else {
        if (loggingService.isDebugEnabled())
          loggingService.debug("consclassifications was NOT NULL Consolidating :"); 
        //printConsolidation(consclassifications," Consolidated Classification before adding :");
        consclassifications=getConsolidatedClassification(regclassifications,consclassifications);
        //printConsolidation(consclassifications," Consolidated Classification after adding ::");
      }
      loggingService.debug("Done with Classification.Going to start on Source :");
      if(consSources==null) {
        loggingService.debug("Consolidated Sources is null :");
        if(regSources!=null) {
          loggingService.debug("Registration source is NOT NULL:");
          consSources=new Source[regSources.length];
          System.arraycopy(regSources,0,consSources,0,regSources.length);
          Source tempsrc=null;
          for(int i=0;i<consSources.length;i++) {
            loggingService.debug("Looking if source has any ref in Additional data at source index :"+ i); 
            tempsrc=consSources[i];
            loggingService.debug("Looking if source has any ref in REG Additional data at source "+ tempsrc.toString()); 
            int index=indexOfAgentReference(tempsrc.getIdent(),regAddData);
            loggingService.debug("Found source has reference in REG ADDITIONAL DATA  at index:"+index); 
            if(index!=-1){
              loggingService.debug("source has a reference in REG additional data :");
              if(consAddData!=null) {
                loggingService.debug("Consolidated Additional Data is NOT  null && index for agent reference in Reg additionaldata is  :"+index );
                AdditionalData tmpdata=null;
                loggingService.debug("Going to look if Reg Additional data is alreday in Consolidate Additional dta :");
                tmpdata=regAddData[index];
                int addindex=indexOfAdditionalData(tmpdata,consAddData);
                if(addindex!=-1) {
                  loggingService.debug("Found  Reg Addition data in Consolidated Additional data at index  :"+addindex); 
                  AdditionalData existdata=consAddData[addindex]; 
                  loggingService.debug(" Going to get agent info of Consolidated Additional data :");
                  org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(existdata);
                  if(agentinfo!=null) {
                    loggingService.debug("Got agent info of Consolidated Additional data :");  
                    String [] existingref=agentinfo.getRefIdents();
                    if(existingref!=null) {
                      loggingService.debug("Agent info and reference array is not null for existing additional data :");
                      String [] newref=new String[existingref.length+1];
                      System.arraycopy(existingref,0,newref,0,existingref.length);
                      newref[existingref.length]=tempsrc.getIdent();
                      agentinfo.setRefIdents(newref);
                    }
                    else {
                      loggingService.debug("Agent info is not null but ref is null in existing additional data :"); 
                      String [] newref=new String[1];
                      newref[0]=tempsrc.getIdent();
                      agentinfo.setRefIdents(newref);
                    }
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agentinfo);
                    consAddData[addindex]=newAdddata;
                  }
                  else {
                    loggingService.debug("Additional data are equal but  agent info is NULL :");
                  }
                }
                else {
                  loggingService.debug("Could not find  Reg Addition data in Consolidated Additional data. Adding to Consolidate Additional data   :"); 
                  AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                  System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                  org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(tmpdata);
                  String [] newref=new String[1];
                  newref[0]=tempsrc.getIdent();
                  agentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agentinfo);
                  tempdata[consAddData.length]=newAdddata;
                  consAddData=tempdata;
                }
		  
              }
              else {
                loggingService.debug("Consolidated Additional Data is null . Adding reg Additional data to consolidated additional data  :");
                AdditionalData [] tempdata=new AdditionalData[1];
                AdditionalData tmpdata=null;
                tmpdata=regAddData[index];
                org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(tmpdata);
                String [] newref=new String[1];
                newref[0]=tempsrc.getIdent();
                agentinfo.setRefIdents(newref);
                AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,agentinfo);
                tempdata[0]=newAdddata;
                consAddData=tempdata;
		   
              }
            }
          }
        }
        else {
          loggingService.debug("Reg source is null : cannot do any thing :");
        }
      }
      else {
        if (loggingService.isDebugEnabled())
          loggingService.debug("consolidated Sources was NOT NULL Consolidating  :"); 
        if(regSources!=null) {
          loggingService.debug("Registration source is not null:");
          //Source tempsource=null;
          int sourceindex=-1;
          for(int i=0;i<regSources.length;i++) {
            sourceindex=getIndexOfSource(regSources[i],consSources);
            if(sourceindex!=-1) {
              loggingService.debug("Found reg source in Consolidated source :"); 
              if(consAddData!=null) {
                loggingService.debug("Consolidate Add Data is not null . Found Reg source in Consolidated Source at index :"+sourceindex );
                int newagentrefindex=indexOfAgentReference(regSources[i].getIdent(),regAddData);
                loggingService.debug("Found reference of Reg source in Reg  Additional data at index :"+newagentrefindex); 
                int existingrefindex=indexOfAgentReference(consSources[sourceindex].getIdent(),consAddData);
                loggingService.debug("Found reference of Consolidated source in Consolidate  Additional data at index :"+existingrefindex); 
                if((newagentrefindex!=-1)&&(existingrefindex!=-1)){
                  loggingService.debug("##### Both new source and existing source has ref in additional data :");
                  org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                  org.cougaar.core.security.monitoring.idmef.Agent existingagentinfo=getAgent(consAddData[existingrefindex]);
                  boolean equal=areAgentInfoEqual(newagentinfo,existingagentinfo);
                  if(!equal) {
                    loggingService.debug("Source are equal but agent info are not equal:");
                    AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                    System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                    String [] newref=new String[1];
                    newref[0]=consSources[sourceindex].getIdent();
                    newagentinfo.setRefIdents(newref);
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,newagentinfo);
                    tempdata[consAddData.length]=newAdddata;
                    consAddData=tempdata;
                  }
                  else {
                    loggingService.debug("Both the source and add data are equal do nothing :");
                  }
                }
                else {
                  loggingService.debug("Source are equal BUT one of source has no refenece in Additional data :");
                  if((existingrefindex==-1)&&(newagentrefindex!=-1)) {
                    loggingService.debug("Consiolidated source has no ref in add data .Adding add data to consolidate Add Data:");
                    org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                    AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                    System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                    String [] newref=new String[1];
                    newref[0]=consSources[sourceindex].getIdent();
                    newagentinfo.setRefIdents(newref);
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,newagentinfo);
                    tempdata[consAddData.length]=newAdddata;
                    consAddData=tempdata;
                  }
                }
              }
              else {
                loggingService.debug("Consolidate Add Data is NULL  .:");
                int newagentrefindex=indexOfAgentReference(regSources[i].getIdent(),regAddData);
                loggingService.debug("Reg source has reference in ref Additional data at index :"+newagentrefindex );
                if(newagentrefindex!=-1) {
                  org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                  AdditionalData [] tempdata=new AdditionalData[1];
                  AdditionalData tmpdata=null;
                  tmpdata=regAddData[newagentrefindex];
                  String [] newref=new String[1];
                  newref[0]=regSources[i].getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,newagentinfo);
                  tempdata[0]=newAdddata;
                  consAddData=tempdata;
                }
		  
              }
            }
            else {
              loggingService.debug("New source does not exist in Consolidated Source :");
              Source newSource=regSources[i];
              Source[] tempsrc=new Source[consSources.length+1];
              System.arraycopy(consSources,0,tempsrc,0,consSources.length);
              tempsrc[consSources.length]=newSource;
              consSources=tempsrc;
              int newagentrefindex=indexOfAgentReference(regSources[i].getIdent(),regAddData);
              if(newagentrefindex!=-1) {
                org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                if(consAddData!=null) {
                  loggingService.debug("New source does not exist in Consolidated Source && Consolidated Additional data is not null:");
                  AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                  System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                  String [] newref=new String[1];
                  newref[0]=newSource.getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,newagentinfo);
                  tempdata[consAddData.length]=newAdddata;
                  consAddData=tempdata;
		    
                }
                else {
                  loggingService.debug("New source does not exist in Consolidated Source && Consolidated Additional data NULL NULL:");
                  AdditionalData [] tempdata=new AdditionalData[1];
                  String [] newref=new String[1];
                  newref[0]=newSource.getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.SOURCE_MEANING,newagentinfo);
                  tempdata[0]=newAdddata;
                  consAddData=tempdata;
		    
                }
              }
            }
          }
          // consSources=getConsolidateSources(regSources,consSources,consAddData,regAddData);
        }
      }
	
      loggingService.debug(" Done with Source .Going to start on Target ++++++++++++++++++++++++++++++++++:");
      if(consTargets==null) {
        loggingService.debug("Consolidated Target is null :");
        if(regTargets!=null) {
          loggingService.debug("registration target is NOT NULL:");
          consTargets=new Target[regTargets.length];
          System.arraycopy(regTargets,0,consTargets,0,regTargets.length);
          Target temptarget=null;
          for(int i=0;i<consTargets.length;i++) {
            loggingService.debug(" Looking if cons Target  has any ref in Additional data at cons target index :"+ i); 
            temptarget=consTargets[i];
            loggingService.debug("Looking if cons Targets  has any ref in REG Additional data at target "+ temptarget.toString()); 
            int index=indexOfAgentReference(temptarget.getIdent(),regAddData);
            loggingService.debug("Found Target has reference in REG ADDITIONAL DATA  at index:"+index); 
            if(index!=-1){
              loggingService.debug("target  has a reference in REG additional data :");
              if(consAddData!=null) {
                loggingService.debug("Consolidated Additional Data is NOT  null && index for agent reference in Reg additionaldata is  :"+index );
                AdditionalData tmpdata=null;
                loggingService.debug("Going to look if Reg Additional data is alreday in Consolidate Additional dta :");
                tmpdata=regAddData[index];
                int addindex=indexOfAdditionalData(tmpdata,consAddData);
                if(addindex!=-1) {
                  loggingService.debug("Found  Reg Addition data in Consolidated Additional data at index  :"+addindex); 
                  AdditionalData existdata=consAddData[addindex]; 
                  loggingService.debug("Going to get agent info of Consolidated Additional data :");
                  org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(existdata);
                  if(agentinfo!=null) {
                    loggingService.debug("Got agent info of Consolidated Additional data :");  
                    String [] existingref=agentinfo.getRefIdents();
                    if(existingref!=null) {
                      loggingService.debug("Agent info and reference array is not null for existing additional data :");
                      String [] newref=new String[existingref.length+1];
                      System.arraycopy(existingref,0,newref,0,existingref.length);
                      newref[existingref.length]=temptarget.getIdent();
                      agentinfo.setRefIdents(newref);
                    }
                    else {
                      loggingService.debug("Agent info is not null but ref is null in existing additional data :"); 
                      String [] newref=new String[1];
                      newref[0]=temptarget.getIdent();
                      agentinfo.setRefIdents(newref);
                    }
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,agentinfo);
                    consAddData[addindex]=newAdddata;
                  }
                  else {
                    loggingService.debug("Additional data are equal but is not agent info :");
                  }
                }
                else {
                  loggingService.debug("Could not find  Reg Addition data in Consolidated Additional data. Adding to Consolidate Additional data   :"); 
                  AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                  System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                  org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(tmpdata);
                  String [] newref=new String[1];
                  newref[0]=temptarget.getIdent();
                  agentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,agentinfo);
                  tempdata[consAddData.length]=newAdddata;
                  consAddData=tempdata;
                }
		  
              }
              else {
                loggingService.debug("Consolidated Additional Data is null . Adding reg Additional data to consolidated additional data  :");
                AdditionalData [] tempdata=new AdditionalData[1];
                AdditionalData tmpdata=null;
                tmpdata=regAddData[index];
                org.cougaar.core.security.monitoring.idmef.Agent agentinfo=getAgent(tmpdata);
                String [] newref=new String[1];
                newref[0]=temptarget.getIdent();
                agentinfo.setRefIdents(newref);
                AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,agentinfo);
                tempdata[0]=newAdddata;
                consAddData=tempdata;
		   
              }
            }
          }
        }
        else {
          loggingService.debug("##### Reg Target is null : cannot do any thing :");
        }
      }
      else {
        if (loggingService.isDebugEnabled())
          loggingService.debug("consolidated Target was NOT NULL Consolidating :"); 
        if(regTargets!=null) {
          loggingService.debug("Registration Target  is not null:");
          //Source tempsource=null;
          int targetindex=-1;
          for(int i=0;i<regTargets.length;i++) {
            targetindex=getIndexOfTarget(regTargets[i],consTargets);
            if(targetindex!=-1) {
              loggingService.debug("Found reg Target in Consolidated Targete :"); 
              if(consAddData!=null) {
                loggingService.debug("Consolidate Add Data is not null . Found Reg Target in Consolidated Target at index :"+targetindex );
                int newagentrefindex=indexOfAgentReference(regTargets[i].getIdent(),regAddData);
                loggingService.debug("Found reference of Reg Target in Reg  Additional data at index :"+newagentrefindex); 
                int existingrefindex=indexOfAgentReference(consTargets[targetindex].getIdent(),consAddData);
                loggingService.debug("Found reference of Consolidated Target in Consolidate  Additional data at index :"+existingrefindex); 
                if((newagentrefindex!=-1)&&(existingrefindex!=-1)){
                  loggingService.debug("Both new target and existing target has ref in additional data :");
                  org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                  org.cougaar.core.security.monitoring.idmef.Agent existingagentinfo=getAgent(consAddData[existingrefindex]);
                  boolean equal=areAgentInfoEqual(newagentinfo,existingagentinfo);
                  if(!equal) {
                    loggingService.debug("Target are equal but agent info are not equal:");
                    AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                    System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                    String [] newref=new String[1];
                    newref[0]=consTargets[targetindex].getIdent();
                    newagentinfo.setRefIdents(newref);
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,newagentinfo);
                    tempdata[consAddData.length]=newAdddata;
                    consAddData=tempdata;
                  }
                  else {
                    loggingService.debug("Both Target and add data are equal do nothing :");
                  }
                }
                else {
                  loggingService.debug("Target are equal BUT one of Target has no refenece in Additional data :");
                  if((existingrefindex==-1)&&(newagentrefindex!=-1)) {
                    loggingService.debug("Consiolidated target has no ref in add data .Adding add data to consolidate Add Data:");
                    org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                    AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                    System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                    String [] newref=new String[1];
                    newref[0]=consTargets[targetindex].getIdent();
                    newagentinfo.setRefIdents(newref);
                    AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,newagentinfo);
                    tempdata[consAddData.length]=newAdddata;
                    consAddData=tempdata;
                  }
                }
              }
              else {
                loggingService.debug("Consolidate Add Data is NULL  .:");
                int newagentrefindex=indexOfAgentReference(regTargets[i].getIdent(),regAddData);
                loggingService.debug("Reg Target has reference in ref Additional data at index :"+newagentrefindex );
                if(newagentrefindex!=-1) {
                  org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                  AdditionalData [] tempdata=new AdditionalData[1];
                  AdditionalData tmpdata=null;
                  tmpdata=regAddData[newagentrefindex];
                  String [] newref=new String[1];
                  newref[0]=regTargets[i].getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,newagentinfo);
                  tempdata[0]=newAdddata;
                  consAddData=tempdata;
                }
		  
              }
            }
            else {
              loggingService.debug("New target does not exist in Consolidated Targets :");
              Target newTarget=regTargets[i];
              Target [] temptarget=new Target[consTargets.length+1];
              System.arraycopy(consTargets,0,temptarget,0,consTargets.length);
              temptarget[consTargets.length]=newTarget;
              consTargets=temptarget;
              int newagentrefindex=indexOfAgentReference(regTargets[i].getIdent(),regAddData);
              if(newagentrefindex!=-1) {
                org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=getAgent(regAddData[newagentrefindex]);
                if(consAddData!=null) {
                  loggingService.debug("New target does not exist in Consolidated Target && Consolidated Additional data is not null:");
                  AdditionalData [] tempdata=new AdditionalData[consAddData.length+1];
                  System.arraycopy(consAddData,0,tempdata,0,consAddData.length);
                  String [] newref=new String[1];
                  newref[0]=newTarget.getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,newagentinfo);
                  tempdata[consAddData.length]=newAdddata;
                  consAddData=tempdata;
		    
                }
                else {
                  loggingService.debug("New target does not exist in Consolidated Target  && Consolidated Additional data NULL NULL:");
                  AdditionalData [] tempdata=new AdditionalData[1];
                  String [] newref=new String[1];
                  newref[0]=newTarget.getIdent();
                  newagentinfo.setRefIdents(newref);
                  AdditionalData newAdddata=createAdditionalData(org.cougaar.core.security.monitoring.idmef.Agent.TARGET_MEANING,newagentinfo);
                  tempdata[0]=newAdddata;
                  consAddData=tempdata;
		    
                }
              }
            }
          }
        }
      }
      loggingService.debug("Going to get next key in capabilities hash map:");
    }
    if(consclassifications!=null) {
      if(consclassifications.length>0) {
        consCapabilities.setClassifications(consclassifications);
        consCapabilities.setSources(consSources);
        consCapabilities.setTargets(consTargets);
        consCapabilities.setAdditionalData(consAddData);
        Analyzer analyzer=new Analyzer();
        analyzer.setAnalyzerid(myAddress.toString());
        consCapabilities.setAnalyzer(analyzer);
        consclassifications=consCapabilities.getClassifications();
        //printConsolidation(consclassifications," consolidated classification after processing is :");
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Relay to be created for address :"+_managerAddress.toString()); 
        }
        if(_managerAddress!=null) {
          addOrUpdateRelay(factory.newEvent(consCapabilities), factory);
        }
      }
    } // end while(keys.hasMoreElements())
  }
  
  private org.cougaar.core.security.monitoring.idmef.Agent getAgent(AdditionalData data) {
    org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
    if(data==null) {
      return agentinfo;
    }
    if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
      if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
        agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
      }
    }
    return agentinfo;
  }
  
  private AdditionalData createAdditionalData(String meaning, org.cougaar.core.security.monitoring.idmef.Agent infoagent) {
    AdditionalData data=null;
    if(infoagent==null) {
      return data;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    //Event event=null;
    IdmefMessageFactory idmeffactory=factory.getIdmefMessageFactory();
    data=idmeffactory.createAdditionalData(meaning,infoagent);
    return data;
  }

  private int indexOfAdditionalData(AdditionalData newData,AdditionalData[] additionaldata) {
    int index=-1;
    if(additionaldata==null) {
      return index;
    }
    org.cougaar.core.security.monitoring.idmef.Agent newagentinfo=null;
    if((!(newData.getType().equalsIgnoreCase("xml")))&&(!(newData.getXMLData()!=null))) {
      return index;
    }
    else {
      if(newData.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
        newagentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)newData.getXMLData();
      }
      else 
        return index;	
    }
    AdditionalData data=null;
    org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
    for(int i=0;i<additionaldata.length;i++) {
      data=additionaldata[i];
      if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
        if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){ 
          agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          if((agentinfo.getName().equalsIgnoreCase(newagentinfo.getName()))&&
             (agentinfo.getDescription().equalsIgnoreCase(newagentinfo.getDescription()))&&
             (agentinfo.getAddress().equals(newagentinfo.getAddress()))) {
            index=i;
            break;
          }
        }
      }
    }
    return index;
  }
  
  private boolean areAgentInfoEqual(org.cougaar.core.security.monitoring.idmef.Agent newagent,
                                    org.cougaar.core.security.monitoring.idmef.Agent existingagent) {
    boolean equal=false;
    boolean nameequal=false;;
    boolean addressequal=true;
    if((newagent==null)||(existingagent==null)) {
      return false;
    }
    String existingagentname=null;
    String newagentname=null;
    existingagentname=existingagent.getName();
    newagentname=newagent.getName();
    if((existingagentname==null)||(newagentname==null)) {
      return false;
    }
    if(existingagentname.equalsIgnoreCase(newagentname)) {
      nameequal=true;
    }
    Address existingaddress=null;
    Address newaddress=null;
    existingaddress=existingagent.getAddress();
    newaddress=newagent.getAddress();
    if( (existingaddress == null) || (newaddress == null)) {
      return false;
    }
    if(existingaddress.equals(newaddress)) {
      addressequal=true;
    }
    if(nameequal && addressequal) {
      equal=true;
    }
    return equal;
  }
  private int  indexOfAgentReference(String ident,AdditionalData[] additionaldata) {
    loggingService.debug("##### indexOfAgentReference function called  with :"+ ident); 
    int index=-1;
    if(additionaldata==null) {
      loggingService.debug("Additional data is null in function indexOfAgentReference:");
      return index;
    }
    AdditionalData data=null;
    org.cougaar.core.security.monitoring.idmef.Agent agentinfo=null;
    for(int i=0;i<additionaldata.length;i++) {
      data=additionaldata[i];
      //loggingService.debug(" additional data at "+i + " data is  :"+ data.toString());
      if((data.getType().equalsIgnoreCase("xml"))&&(data.getXMLData()!=null)) {
        loggingService.debug(" additional data is xml and it is not null:");
        if(data.getXMLData() instanceof org.cougaar.core.security.monitoring.idmef.Agent){
          //loggingService.debug(" additional data is of type idmef agent:");
          agentinfo=( org.cougaar.core.security.monitoring.idmef.Agent)data.getXMLData();
          String [] ref=agentinfo.getRefIdents();
          if(ref!=null) {
            for(int j=0;j<ref.length;j++) {
              if(ident.equals(ref[j]) ) {
                //loggingService.debug("found reference at :" + i +"for ident :"+ ident);
                index=i;
                break;
              }
            }
          }
        }
        else {
          loggingService.debug("Not an instance of idmef.Agent in indexOfAgentReference");
        }
      }
      else {
        loggingService.debug("Additional data is not of type xml:");
      }
    }
    return index;
  } 
  
  public ConsolidatedCapabilities createConsolidatedCapabilities() {
    DomainService service=getDomainService();
    if(service==null) {
      if (loggingService.isDebugEnabled())
        loggingService.debug(" Got service as null in CapabilitiesConsolidationPlugin :" +myAddress.toString());
      return null;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    ConsolidatedCapabilities conscapabilities=imessage.createConsolidatedCapabilities();
    conscapabilities.setType(IdmefMessageFactory.SecurityMgrType);
    return conscapabilities;
  }

    
  public void printConsolidation(Classification[] classifications, String msg) {
    if (loggingService.isDebugEnabled())
      loggingService.debug(msg);
    Classification classification=null;
    for(int i=0;i<classifications.length;i++){
      classification= classifications[i];
      converttoString( classification);
    }
  }

  
 
  public Classification[] getConsolidatedClassification( Classification[] newcapabilities ,Classification[] existingcapabilities ) {

    //Arrays.sort((Object[])existingcapabilities);
    //printConsolidation(newcapabilities,"New Capabilities:");
    //printConsolidation(existingcapabilities,"Existing  Capabilities:");
    Vector indexes=new Vector();
    Classification existingclas=null;
    Classification newclas=null;
    int index=-1;
    boolean found=false;
    for(int i=0;i<newcapabilities.length;i++){
      found=false;
      newclas=newcapabilities[i];
      for(int j=0;j<existingcapabilities.length;j++) {
        existingclas=existingcapabilities[j];
        if(!existingclas.equals(newclas)) {
          continue;
        }
		
        found=true;
        break;
		
      }
      if(!found) {
        if (loggingService.isDebugEnabled())
          loggingService.debug(" new  capabilities :");
        converttoString(newclas);
        indexes.add(newclas);
      }
	   
    }
    Classification[] consolidate=new Classification[existingcapabilities.length+indexes.size()];
    Classification clas=null;
    System.arraycopy(existingcapabilities,0,consolidate,0,existingcapabilities.length);
    index=existingcapabilities.length;
    for(int i=0;i<indexes.size();i++){
      clas = (Classification) indexes.elementAt(i);
      consolidate[i+index]=clas;
      // log.debug("New Classifications are :"+clas.toString());
    }
    return consolidate;
  }
  
  
  public int getIndexOfTarget(Target newTarget ,Target[] existingTargets) {
    int index=-1;
    if(newTarget==null) {
      return index;
    } 
    Target existingTarget=null;
    for(int i=0;i<existingTargets.length;i++) {
      existingTarget=existingTargets[i];
      if(!existingTarget.equals(newTarget)) {
        continue;
      }
      index=i;
      break;
    }
    return index;
  }
  
  public int getIndexOfSource(Source newSource ,Source[] existingSources) {
    int index=-1;
    if(newSource==null) {
      return index;
    } 
    Source existingSource=null;
    for(int i=0;i<existingSources.length;i++) {
      existingSource=existingSources[i];
      if(!existingSource.equals(newSource)) {
        continue;
      }
      index=i;
      break;
    }
    return index;
  }
  public Source[] getConsolidateSources(Source[] newSources, Source[] existingSources,
                                        AdditionalData[] newAddData,AdditionalData[] existingAddData) {
    if(newSources==null) {
      return existingSources;
    }
    Vector indexes=new Vector();
    Source existingSource=null;
    Source newSource=null;
    int index=-1;
    boolean found=false;
    for(int i=0;i<newSources.length;i++){
      found=false;
      newSource=newSources[i];
      for(int j=0;j<existingSources.length;j++) {
        existingSource=existingSources[j];
        if(!existingSource.equals(newSource)) {
          continue;
        }
        found=true;
        break;
      }
      if(!found) {
        if (loggingService.isDebugEnabled())
          loggingService.debug("Found new Source:");
        //converttoString(newclas);
        indexes.add(newSource);
      }
    }
    Source[] consSources=new Source[existingSources.length+indexes.size()];
    Source source=null;
    System.arraycopy(existingSources,0,consSources,0,existingSources.length);
    index=existingSources.length;
    for(int i=0;i<indexes.size();i++){
      source = (Source) indexes.elementAt(i);
      consSources[i+index]=source;
    }
    return consSources;
  }
  
  public Target[] getConsolidatedTargets(Target[] newTargets, Target[] existingTargets ) {
    if(newTargets==null) {
      return existingTargets;
    }
    Vector indexes=new Vector();
    Target existingTarget=null;
    Target newTarget=null;
    int index=-1;
    boolean found=false;
    for(int i=0;i<newTargets.length;i++){
      found=false;
      newTarget=newTargets[i];
      for(int j=0;j<existingTargets.length;j++) {
        existingTarget=existingTargets[j];
        if(!existingTarget.equals(newTarget)) {
          continue;
        }
        found=true;
        break;
      }
      if(!found) {
        if (loggingService.isDebugEnabled())
          loggingService.debug("Found new Target:");
        //converttoString(newclas);
        indexes.add(newTarget);
      }
    }
    Target[] consTargets=new Target[existingTargets.length+indexes.size()];
    Target target=null;
    System.arraycopy(existingTargets,0,consTargets,0,existingTargets.length);
    index=existingTargets.length;
    for(int i=0;i<indexes.size();i++){
      target = (Target) indexes.elementAt(i);
      consTargets[i+index]=target;
    }
    return consTargets;
  }

  public void converttoString(Classification classification) {
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(" Classification origin :"+classification.getOrigin());
      loggingService.debug(" Classification Name :"+classification.getName());
      loggingService.debug(" Classification URL :"+classification.getUrl());
    }
  }
  
  private void addOrUpdateRelay(Event event, CmrFactory factory) {
    if (loggingService.isDebugEnabled()){
      //loggingService.debug("addOrUpdateRelay"+ myAddress.toString()+ "data is :" + event.toString());
      loggingService.debug("addOrUpdateRelay"+ myAddress.toString());
    }
    CmrRelay relay = null;
    // Find the (one) outgoing relay
    Iterator iter = capabilitiesRelays.iterator();
    while (iter.hasNext()) {
      CmrRelay aRelay = (CmrRelay)iter.next();
      if (aRelay.getSource().equals(myAddress)) {
        relay = aRelay;
        break;
      }
    }
    if (relay == null) {
      if (loggingService.isDebugEnabled()) {
        //loggingService.debug(" No relay was present creating one for Event "+ event.toString());
      }
      relay = factory.newCmrRelay(event, _managerAddress);
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" No relay was present creating one  "+ relay.toString());
      }
      if(_managerAddress!=null) {
        loggingService.info(" Creating relay to :"+ _managerAddress.toString());
        getBlackboardService().publishAdd(relay);
      }
    } else {
      //loggingService.debug(" relay was present Updating event  Event "+ event.toString());
      relay.updateContent(event, null);
      loggingService.info(" Modifying  relay to :"+ relay.getTarget());
      getBlackboardService().publishChange(relay);
    }
  }
  
  private void updateRelayedCapabilities() {
    if (capabilitiesRelays.hasChanged()) {
      if (loggingService.isDebugEnabled())
        loggingService.debug("capabilitiesRelays has changed in CCP at  "+ myAddress.toString());
      CmrRelay relay;
      // New relays
      Iterator iter = capabilitiesRelays.getAddedCollection().iterator();
      while (iter.hasNext()) {
        relay = (CmrRelay)iter.next();
        if (!relay.getSource().equals(myAddress)) { // make sure it's remote, not local
          loggingService.debug(" printing receive relay which is not local:====>"
                               +relay.getContent().toString());
          getBlackboardService().publishAdd(relay.getContent());
        }
      }
           
      // Changed relays
      iter = capabilitiesRelays.getChangedCollection().iterator();
      while (iter.hasNext()) {
        relay = (CmrRelay)iter.next();
        if (!relay.getSource().equals(myAddress)) {
          Event oldCapabilities = findEventFrom(relay.getSource());
          if (oldCapabilities != null)
            getBlackboardService().publishRemove(oldCapabilities);
          loggingService.debug(" printing changed  relay which is not local:=======>"
                               +relay.getContent().toString());
          getBlackboardService().publishAdd(relay.getContent());
        }
      }
      // Removed relays
      iter = capabilitiesRelays.getRemovedCollection().iterator();
      while (iter.hasNext()) {
        relay = (CmrRelay)iter.next();
        if (!relay.getSource().equals(myAddress)) {
          Event oldCapabilities = findEventFrom(relay.getSource());
          if (oldCapabilities != null)
            getBlackboardService().publishRemove(oldCapabilities);
        }
      }
    }
  }
  
/*
  private Community getMySecurityCommunity() {
  Community mySecurityCommunity= _csu.getSecurityCommunity(myAddress.toString());
  if(mySecurityCommunity==null) {
  loggingService.warn(" Canot get my role as Manager in any Security Community  :"+myAddress.toString() );
  }
  return mySecurityCommunity;
  }
*/ 
  
  /**
   * Find the previous AgentRegistration Event from this source (if any)
   */
  private Event findEventFrom(MessageAddress source) {
    Iterator iter = this.agentRegistrations.iterator();
    while (iter.hasNext()) {
      Event event = (Event)iter.next();
      if (event.getSource().equals(source))
        return event;
    }
    return null;
  }
    
  public void printhash(CapabilitiesObject cap) {
    Enumeration keys=cap.keys();
    String key=null;
    RegistrationAlert registration=null;
    loggingService.debug(" CAPABILITIES OBJECT IN ADDRESS :"+myAddress.toString());
    while(keys.hasMoreElements()) {
      key=(String)keys.nextElement();
      if (loggingService.isDebugEnabled())
        loggingService.debug(" KEY IN CAPABILITIES OBJECT IS :"+key);
      registration=(RegistrationAlert)cap.get(key);
      loggingService.debug(" data of reg alert is :"+registration.toString());
    }
    
  }

  private void registerManager() {
    CommunityServiceUtilListener listener = new CommunityServiceUtilListener() {
	public void getResponse(Set entities) {
	  Iterator it = entities.iterator();
	  if (entities.size() == 0) {
	    loggingService.warn("Could not find a security manager");
	  }
	  else if (entities.size() > 1) {
	    loggingService.warn("Found more than one security manager");
	  }
	  else {
	    Entity entity = (Entity) it.next();
	    MessageAddress addr = MessageAddress.
	      getMessageAddress(entity.getName());
            loggingService.info("Setting MGR address to : "+addr);
	    setManagerAddress(addr);
	    _csu.releaseServices();
	  }
	}
      };
    if(loggingService.isDebugEnabled()){
      loggingService.debug("Calling CommunityService util findSecurityManager :"+ myAddress);
    }
    _csu.findSecurityManager(CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE,listener);
  }

  private class RegistrationListener implements CommunityServiceUtilListener {
    public void getResponse(Set entities) {
      if (entities == null || entities.isEmpty()) {
        registerManager();
      } else {
        loggingService.info("I am the root security manager. " +
                            "Not registering.");
      }
    }
  }
}// class CapabilitiesConsolidationPlugin
