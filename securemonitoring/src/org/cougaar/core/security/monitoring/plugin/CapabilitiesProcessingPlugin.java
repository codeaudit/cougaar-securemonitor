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

import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NotificationObject;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;



/**
 * A predicate that matches all "Event object with registration "
 */
class CapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof Registration){
        return true;
      }
    }
    return ret;
  }
}
/**
   Subscribes to Relay with RegistrationAlert 
*/
class CapabilitiesRelayPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      if(relay.getContent() instanceof Event) {
        Event event = (Event)relay.getContent();
        ret = (event.getEvent() instanceof Registration);
      }
      else {
        return ret;
      }
    }
    return ret;
  }
}

/**
 * A predicate that matches all CapabilitiesObject
 */
class CompleteCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}

/**
 * Predicate that matches all ConsolidateCapabilities
 *
 */
class ConsolidatedCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof Event ) {
      Event e=(Event)o;
      IDMEF_Message msg=e.getEvent();
      if(msg instanceof AgentRegistration){
        return true;
      }
    }
    return ret;
  }
}

class NotificationPredicate implements UnaryPredicate {
  public boolean execute(Object o) {
    boolean ret = false; 
   if (o instanceof NotificationObject ) {
      return true;
    }
    return ret;
  }
}


/**
 *
 **/

public class CapabilitiesProcessingPlugin extends ComponentPlugin {
  private static String MGR_ROLE = "Manager";

  // The domainService acts as a provider of domain factory services
  private DomainService domainService = null;
  private CommunityService communityService=null;
  private IncrementalSubscription capabilities;
  private IncrementalSubscription completecapabilities;
  private IncrementalSubscription subordinatecapabilities;
  private IncrementalSubscription capabilitiesRelays;
  private IncrementalSubscription notification;
  private int firstobject=0;
  private LoggingService loggingService;
  private EventService   eventService;
  private MessageAddress myAddress=null;
  private Object param;
  
  private MessageAddress mgrAddress;
//  private Community mySecurityCommunity=null;
  /*
    not used any where in code 
  private CommunityServiceUtil _csu;
  */
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
    this.communityService=cs;
  }

        
  /**
   * 
   */
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    eventService = (EventService)getBindingSite().getServiceBroker().getService
      (this, EventService.class, null);
    myAddress = getAgentIdentifier();
    /*
      CommunityServiceUtil not used any where in the code 
    _csu = new CommunityServiceUtil(getServiceBroker());
    */
    loggingService.debug("setupSubscriptions of CapabilitiesProcessingPlugin called :"
        + myAddress.toString()); 
/*
    mySecurityCommunity = getMySecurityCommunity();
    if(mySecurityCommunity==null) {
      loggingService.error("No Info about My  SecurityCommunity in " +
			   "CapabilitiesProcessingPlugin"+
			   " : Cannot send messaged!"+myAddress.toString());  
      // return;
    }
    else {
      loggingService.debug(" My security community :"+mySecurityCommunity.getName()
			   +" agent name :"+myAddress.toString());
    }
*/
   
    Collection capabilitiescollection = getBlackboardService().query(new CompleteCapabilitiesPredicate());
    if(capabilitiescollection.isEmpty()){
      if(getBlackboardService().didRehydrate()) {
      	loggingService.error(" BlackBoard Rehydrated but there is no capabilities Object:");
      	return;
      }
      else {
      	CapabilitiesObject object=new CapabilitiesObject();
      	getBlackboardService().publishAdd(object);
      }
    }
    capabilities= (IncrementalSubscription)getBlackboardService().subscribe
      (new CapabilitiesPredicate());
    capabilitiesRelays= (IncrementalSubscription)getBlackboardService().subscribe
      (new CapabilitiesRelayPredicate());
    completecapabilities= (IncrementalSubscription)getBlackboardService().subscribe
      (new CompleteCapabilitiesPredicate() );
    subordinatecapabilities=(IncrementalSubscription)getBlackboardService().subscribe
      (new ConsolidatedCapabilitiesPredicate()); 
    notification=(IncrementalSubscription)getBlackboardService().subscribe
      (new NotificationPredicate());
  }


  /**
   * Top level plugin execute loop.  
   */
  protected void execute () {
    
    loggingService.debug("Execute of Capabilities processing plugin called "+myAddress.toString());
  
    updateRelayedCapabilities();

    Event event=null;
    RegistrationAlert registration=null;
    CapabilitiesObject capabilitiesobject=null;
    Collection  capabilities_col=completecapabilities.getCollection();
    //ArrayList list=new ArrayList(capabilities_col);
    boolean modified=false;

    if(( capabilities_col==null)||( capabilities_col.size()==0)){
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("No capabilities object present in capabilities processing plugin:"+
            "RETURNING !"+ myAddress.toString());
      }
      return;
    }

    if( capabilities_col.size()>1) {
      if(loggingService.isDebugEnabled()) {
        loggingService.debug(" Error Multiple capabilities  object on blackboard"+
            "CapabilitiesprocessingPlugin in agent::"
            + myAddress.toString());
        loggingService.debug("CONFUSION ......  CONFUSION!!!!!!!!!!!!! Exiting !!!!!!!!:");
      }
      return;
   
    }
    Iterator iter= capabilities_col.iterator();
    while (iter.hasNext()) {
      capabilitiesobject=(CapabilitiesObject )iter.next();
      break;
    }
    Collection notifications=notification.getAddedCollection();
    if(notifications.size()>0) {
      loggingService.debug("received notification to do publish change:");
      getBlackboardService().publishChange(capabilitiesobject);
      /*
        Iterator notificationiterator =notifications.iterator();
        while( notificationiterator.hasNext()) {
        Object obj=notificationiterator.next();
        getBlackboardService().publishRemove(obj);
        }
      */
    }
   
    //capabilitiesobject=(CapabilitiesObject)list.get(firstobject);
    Enumeration capabilities_enum = capabilities.getAddedList();
    Collection subcol= subordinatecapabilities.getAddedCollection();
    loggingService.debug(" got collection size for sub is :"+subcol.size());
    Iterator  subordinatecapabilities_enum=subcol.iterator();
    
    Analyzer analyzer=null;
    String analyzer_id=null;
    /*
      Process capabilities received from within the agent
    */
    while(capabilities_enum.hasMoreElements()) {
      event=( Event)  capabilities_enum.nextElement();
      if(loggingService.isDebugEnabled()) {
        /*
      	loggingService.debug("Event received is  :"+ event.toString() 
            + "\n in agent "+myAddress.toString());
        */
        loggingService.debug("Event received in agent "+myAddress.toString());
      }
      registration=(RegistrationAlert)event.getEvent();
      analyzer=registration.getAnalyzer();
      analyzer_id=analyzer.getAnalyzerid();
      
      event(registration); // give an event about this

      if(loggingService.isDebugEnabled()) {
	      loggingService.debug(" Got analyzer id -->"+ analyzer_id );
      }
      
      if(capabilitiesobject.containsKey(analyzer_id)) {
      	if(loggingService.isDebugEnabled()) {
      	  loggingService.debug("Analyzer is registered. Registering Analyzer again in agent :"
              +myAddress.toString() 
              +" analyzer id" + analyzer_id );
        }
	  
        RegistrationAlert existingregistartion=(RegistrationAlert)capabilitiesobject.get(analyzer_id);
        if(registration.getOperation_type()==IdmefMessageFactory.addtoregistration)  {
          if(loggingService.isDebugEnabled()) {
            loggingService.debug(" registration type is ADD ");
            //printConsolidation(existingregistartion.getClassifications(),"!before  adding add reg object"); 
            //printConsolidation(registration.getClassifications(),"!!!!!New  add reg object");
          }
          existingregistartion= addtoRegistartion(existingregistartion,registration);
          /*if(loggingService.isDebugEnabled())
            printConsolidation(existingregistartion.getClassifications(),"After adding add reg object"); 
            capabilitiesobject.put(analyzer_id,registration);
          */
        }
        else if(registration.getOperation_type()==IdmefMessageFactory.removefromregistration)  {
          if(loggingService.isDebugEnabled()) {
            loggingService.debug(" registration type is remove");
          }
          // printConsolidation(existingregistartion.getClassifications(),"!!!!!before removing  remove reg object"); 
          //printConsolidation(registration.getClassifications(),"!!!!!New remove  reg object"); 
          existingregistartion= removefromRegistartion(existingregistartion,registration); 
          // printConsolidation(existingregistartion.getClassifications(),"After removing remove reg object");
          // existingregistartion= removefromRegistartion(existingregistartion,registration); 
        }
        modified=true;
        capabilitiesobject.put(analyzer_id,existingregistartion);
      }
      else {
      	if(loggingService.isDebugEnabled()) {
      	  loggingService.debug("Analyzer is not yet registered. Registering Analyzer  in agent :"+myAddress.toString() 
              +" analyzer id" + analyzer_id );
        }
      	modified=true;
      	//printConsolidation(registration.getClassifications(),"!!!!!Classification before reg first time @@@@"); 
      	capabilitiesobject.put(analyzer_id,registration);
      }
    }

    // Process capabilities received from subordinate agent 
    
    boolean subModified = processSubCapabilities(subordinatecapabilities_enum,capabilitiesobject);
 
    if(modified || subModified) {
      loggingService.debug(" CAPABILITIES object is modified publishing change from agent :"+ myAddress.toString());
      getBlackboardService().publishChange(capabilitiesobject);
    }
  }

  private void event(RegistrationAlert registration) {
    if (!eventService.isEventEnabled()) {
      return;
    }
    
    String analyzerId = registration.getAnalyzer().getAnalyzerid();
    String op;
    switch (registration.getOperation_type()) {
    case IdmefMessageFactory.addtoregistration:
      op = "Add";
      break;
    case IdmefMessageFactory.removefromregistration:
      op = "Remove";
      break;
    case IdmefMessageFactory.newregistration:
      op = "New";
      break;
    default:
      op = "Unknown: " + registration.getOperation_type();
    }
    Classification[] caps = registration.getClassifications();
    StringBuffer buf = new StringBuffer();
    buf.append("[STATUS] SecurityManager(");
    buf.append(myAddress.toAddress());
    buf.append(") Analyzer(");
    buf.append(analyzerId);
    buf.append(") Operation(");
    buf.append(op);
    buf.append(") Classifications(");
    if (caps != null) {
      for (int i = 0; i < caps.length; i++) {
        if (i != 0) {
          buf.append(", ");
        } 
        buf.append(caps[i].getName());
      }
    }
    buf.append(")");
    eventService.event(buf.toString());
  }

  public void printConsolidation(Classification[] classifications, String msg) {
    loggingService.debug(msg);
    Classification classification=null;
    for(int i=0;i<classifications.length;i++){
      classification= classifications[i];
      converttoString( classification);
    }
  }

    
  public void converttoString(Classification classification) {
    loggingService.debug(" Classification origin :"+classification.getOrigin());
    loggingService.debug(" Classification Name :"+classification.getName());
    loggingService.debug(" Classification URL :"+classification.getUrl());
  }


  public RegistrationAlert addtoRegistartion(RegistrationAlert existingregObject,RegistrationAlert newregobject) {
	
    Classification [] existingClassifications=existingregObject.getClassifications();
    Source[] existingSources=existingregObject.getSources();
    Target[]existingTargets=existingregObject.getTargets();
    AdditionalData[] existingData=existingregObject.getAdditionalData();
    Classification[] classifications=newregobject.getClassifications();
    Source[] sources=newregobject.getSources();
    Target[] targets=newregobject.getTargets();
    AdditionalData[]data=newregobject.getAdditionalData();
    int existinglength=existingClassifications.length;
    int newlength=classifications.length;
    if(classifications!=null) {
      Classification[] updatedclassification=new Classification[existinglength +newlength];
      System.arraycopy(existingClassifications,0,updatedclassification,0,existinglength);
      System.arraycopy(classifications,0,updatedclassification,existinglength,newlength);
      existingregObject.setClassifications(updatedclassification);
	   
    }

    if(sources!=null) {
      existinglength=existingSources.length;
      newlength=sources.length;
      Source[] updatedsources=new Source[existinglength +newlength];
      System.arraycopy(existingSources,0,updatedsources,0,existinglength);
      System.arraycopy(sources,0,updatedsources,existinglength,newlength);
      existingregObject.setSources(updatedsources);
	    
    }

    if(targets!=null) {
      existinglength=existingTargets.length;
      newlength=targets.length;
      Target[] updatedtargets=new Target[existinglength +newlength];
      System.arraycopy(existingTargets,0,updatedtargets,0,existinglength);
      System.arraycopy(targets,0,updatedtargets,existinglength,newlength);
      existingregObject.setTargets(updatedtargets); 
	    
    }
    if(data!=null) {
      existinglength=existingData.length;
      newlength=data.length;
      AdditionalData[] updateddata=new AdditionalData [existinglength +newlength];
      System.arraycopy(existingData,0,updateddata,0,existinglength);
      System.arraycopy(data,0,updateddata,existinglength,newlength);
      existingregObject.setAdditionalData(updateddata); 
    }

    return existingregObject;
	
  }

 
  public RegistrationAlert removefromRegistartion(RegistrationAlert existingregObject,RegistrationAlert newregobject) {
    Classification [] existingClassifications=existingregObject.getClassifications();
    Source[] existingSources=existingregObject.getSources();
    Target[]existingTargets=existingregObject.getTargets();
    AdditionalData[] existingData=existingregObject.getAdditionalData();
    Classification[] classifications=newregobject.getClassifications();
    Source[] sources=newregobject.getSources();
    Target[] targets=newregobject.getTargets();
    AdditionalData[]data=newregobject.getAdditionalData();
    int existinglength=existingClassifications.length;
    int newlength=classifications.length;
    boolean found= false;
    int foundindex=-1;
    if(classifications!=null){
      Classification newclassification=null;
      Classification existingclassification=null;
      Vector modifiedclassification=new Vector();
      for(int i=0;i<newlength;i++) {
        newclassification=classifications[i];
        found=false;
        foundindex=-1;
        for(int j=0;j<existinglength;j++) {
          existingclassification=existingClassifications[j];
          if(!existingclassification.equals(newclassification)){
            continue;
          }
          loggingService.debug("Found classification to remove:!" + existingclassification.toString());
          found=true;
          foundindex=j;
          break;
        }
		 
        if((found)&&(foundindex!=-1)) {
          loggingService.debug(" Found classification to remove at index  :"+foundindex);
          Classification modifiedClassifications[]=new Classification[existinglength-1];
          System.arraycopy(existingClassifications,0,modifiedClassifications,0,foundindex);
          /* doing an array copy till the index where classification is found and skiping 
             the index where classification is found in existing classification. If the index 
             is the last one there is no need to copy the last classification */
          if((foundindex+1)!=existinglength)
            System.arraycopy(existingClassifications,foundindex+1,modifiedClassifications,foundindex,existinglength-1);
          // printConsolidation(modifiedClassifications,"After removing :###########");
          existinglength=modifiedClassifications.length;
          existingClassifications=modifiedClassifications;
        }	    
      }
      existingregObject.setClassifications(existingClassifications);
    }
    if(sources!=null) {
      existinglength=existingSources.length;
      newlength=sources.length;
      Source existingsource=null;
      Source newsource=null;
      for(int i=0;i<newlength;i++) {
        newsource=sources[i];
        found=false;
        foundindex=-1;
        for(int j=0;j<existinglength;j++) {
          existingsource=existingSources[j];
          if(!existingsource.equals(newsource)){
            continue;
          }
          loggingService.debug("Found Source to remove:");
          found=true;
          foundindex=j;
          break;
        }
		 
        if((found)&&(foundindex!=-1)) {
          loggingService.debug(" Found Siurce to remove at :"+foundindex);
          Source modifiedSources[]=new Source[existinglength-1];
          System.arraycopy(existingSources,0,modifiedSources,0,foundindex);
          /* doing an array copy till the index where classification is found and skiping 
             the index where classification is found in existing classification. If the index 
             is the last one there is no need to copy the last classification */
          if((foundindex+1)!=existinglength)
            System.arraycopy(existingSources,foundindex+1,modifiedSources,foundindex,existinglength-1);
          // printConsolidation(modifiedClassifications,"After removing :###########");
          existinglength=modifiedSources.length;
          existingSources=modifiedSources;
		    
		     
        }
      }
      existingregObject.setSources(existingSources);
	    
    }
    if(targets!=null) {
      existinglength=existingTargets.length;
      newlength=targets.length;
      Target existingtarget=null;
      Target newtarget=null;
      for(int i=0;i<newlength;i++) {
        newtarget=targets[i];
        found=false;
        foundindex=-1;
        for(int j=0;j<existinglength;j++) {
          existingtarget=existingTargets[j];
          if(!existingtarget.equals(newtarget)){
            continue;
          }
          loggingService.debug("Found Target to remove:");
          found=true;
          foundindex=j;
          break;
        }
		 
        if((found)&&(foundindex!=-1)) {
          loggingService.debug(" Found Target  to remove at :"+foundindex);
          Target modifiedTargets[]=new Target[existinglength-1];
          System.arraycopy(existingTargets,0,modifiedTargets,0,foundindex);
          /* doing an array copy till the index where classification is found and skiping 
             the index where classification is found in existing classification. If the index 
             is the last one there is no need to copy the last classification */
          if((foundindex+1)!=existinglength)
            System.arraycopy(existingTargets,foundindex+1,modifiedTargets,foundindex,existinglength-1);
          // printConsolidation(modifiedClassifications,"After removing :###########");
          existinglength=modifiedTargets.length;
          existingTargets=modifiedTargets;
        }
      }
      existingregObject.setTargets(existingTargets);
    }
    
    if(data!=null) {
    }
	
    return existingregObject;

  }

  /*
    Reads RegistrationAlert relay and if it is not local then  it publish the content to the 
    blackboard
  */
  private void updateRelayedCapabilities() {
    if (capabilitiesRelays.hasChanged()) {
      if (loggingService.isDebugEnabled())
        loggingService.debug("CapabilitiesRelays has changed in Capabilities Processing Plugin at address  "+ myAddress.toString());
      CmrRelay relay;
      // New relays
      Iterator iter = capabilitiesRelays.getAddedCollection().iterator();
      while (iter.hasNext()) {
        relay = (CmrRelay)iter.next();
        if (!relay.getSource().equals(myAddress)) { // make sure it's remote, not local
          if (loggingService.isDebugEnabled())
            loggingService.debug(" printing received relay which is not LOCAL :==>");
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
  
  /**
   * Find the previous AgentRegistration Event from this source (if any)
   */
  private Event findEventFrom(MessageAddress source) {
    Iterator iter = this.capabilities.iterator();
    while (iter.hasNext()) {
      Event event = (Event)iter.next();
      if (event.getSource().equals(source))
        return event;
    }
    return null;
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

  public RegistrationAlert getRegistrationAlert(ConsolidatedCapabilities cons) {
    DomainService service=getDomainService();
    if(service==null) {
      loggingService.debug(" Got service as null in  getRegistrationAlert of Capabilities"+
          "ProcessingPlugin  :"+ myAddress.toString());
      return null;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
      
    RegistrationAlert ralert= null;
    
    if(cons == null) {
      loggingService.info("ConsolidatedCapabilities is null!");
      return null;
    } 
    List sources = null;
    List targets = null;
    List classifications = null;
    List data = null;
    if(cons.getSources() != null) {
      sources = Arrays.asList(cons.getSources());
    }
    if(cons.getTargets() != null) {
      targets = Arrays.asList(cons.getTargets());
    }
    if(cons.getClassifications() != null) {
      classifications = Arrays.asList(cons.getClassifications());
    }
    if(cons.getAdditionalData() != null) {
      data = Arrays.asList(cons.getAdditionalData());
    }

    
    ralert=imessage.createRegistrationAlert(cons.getAnalyzer(),
          sources,
          targets,
          classifications,
          data,
          IdmefMessageFactory.newregistration,
          IdmefMessageFactory.SecurityMgrType,
          cons.getAgentName());
    
    return ralert;
  }
  
  /**
   * Process capabilities received from subordinate agent 
   */
  private boolean processSubCapabilities(Iterator subCapablities, CapabilitiesObject capObject) {
    boolean modified = false;
    Event event = null;
    ConsolidatedCapabilities cc = null;
    Analyzer analyzer = null;
    String analyzerId = null;
    
    while(subCapablities.hasNext())  {
      event=( Event)  subCapablities.next();
      if(event.getSource().equals(myAddress)) {
      	loggingService.debug(" $$$$$ recived event from my source address :"+myAddress.toString()
            +" event is :"+event.toString());
      	continue;
      }
      cc = (ConsolidatedCapabilities)event.getEvent(); 
      if(loggingService.isDebugEnabled()) {
	      loggingService.debug(" got consolidatedcapabilities in agent :>"+myAddress.toString() +
            "consolidated capabilities "+ cc.toString()+
            "Analyzer id is "+ cc.getAnalyzer().getAnalyzerid());
      }
      
      /**
	     * Consolidating capabilities from local sensors or subordinate managers
       */
      analyzerId = cc.getAnalyzer().getAnalyzerid();
      if(capObject.containsKey(analyzerId)) {
      	if(loggingService.isDebugEnabled()) {
      	  loggingService.debug(" Agent is already registered :");
      	}
      	RegistrationAlert regAlert = getRegistrationAlert(cc);
      	capObject.put(analyzerId, regAlert);
      	if(loggingService.isDebugEnabled()) {
      	  loggingService.debug(" Replacing RegistrationAlert for analyzer id :"+ analyzerId );
      	}
      	modified = true;
      }
      else {
      	capObject.put(analyzerId, getRegistrationAlert(cc));
      	loggingService.debug(" Agent is not  registered :" + analyzerId);
      	modified = true;
      }
    }
    
    return modified;
  }
}
