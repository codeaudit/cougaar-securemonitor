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
import org.cougaar.core.security.monitoring.blackboard.AggregatedResponse;
import org.cougaar.core.security.monitoring.blackboard.AggregationDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DetailsDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.RemoteConsolidatedEvent;
import org.cougaar.core.security.monitoring.util.DrillDownQueryConstants;
import org.cougaar.core.security.monitoring.util.DrillDownUtils;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;


class AggConsolidatedResponsePredicate implements  UnaryPredicate{
   
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof ConsolidatedEvent ) {
      return true;
    }
    return ret;
  }
}
class NewDetailsDrillDownPredicate implements  UnaryPredicate{
  private MessageAddress agentAddress;
  public  NewDetailsDrillDownPredicate(MessageAddress address){
    agentAddress=address;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    CmrRelay cmrRelay=null;
    if (o instanceof CmrRelay ) {
      cmrRelay=(CmrRelay)o;
      if((!(cmrRelay.getSource().equals(agentAddress)))&&
         (cmrRelay.getContent() instanceof DetailsDrillDownQuery) &&
         (cmrRelay.getResponse()==null )){
        return true;
      }
    }
    return ret;
  }
}
class DetailsDrillDownPredicate implements  UnaryPredicate{
  private MessageAddress agentAddress;
  public  DetailsDrillDownPredicate(MessageAddress address){
    agentAddress=address;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    CmrRelay cmrRelay=null;
    if (o instanceof CmrRelay ) {
      cmrRelay=(CmrRelay)o;
      if((!(cmrRelay.getSource().equals(agentAddress)))&&
         (cmrRelay.getContent() instanceof DetailsDrillDownQuery)){
        return true;
      }
    }
    return ret;
  }
}

class IdmefAndRemoteEventPredicate implements  UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if(o instanceof Event){
      ret= true;
    }
    if(o instanceof RemoteConsolidatedEvent){
      ret= true;
    }
    return ret;
  }
}

public class MnRAggSendRemoteResponse extends MnRAggQueryBase {
/*
  protected LoggingService loggingService;
  protected MessageAddress myAddress;
*/
  private IncrementalSubscription consolidatedResponse;
  private IncrementalSubscription detailedResponse;
  private IncrementalSubscription idmefEventResponse;
  /* 
     public void setLoggingService(LoggingService ls) {
     loggingService = ls; 
     }
  
     public LoggingService getLoggingService() {
     return loggingService; 
     }
  */

  protected synchronized void setupSubscriptions() {
    super.setupSubscriptions();
    consolidatedResponse = (IncrementalSubscription)getBlackboardService().
      subscribe(new AggConsolidatedResponsePredicate());
    detailedResponse = (IncrementalSubscription)getBlackboardService().
      subscribe(new NewDetailsDrillDownPredicate(myAddress));
    idmefEventResponse = (IncrementalSubscription)getBlackboardService().
      subscribe(new IdmefAndRemoteEventPredicate());
  }
  
  protected synchronized void execute() {
    Collection responsecol=null;
    if(consolidatedResponse.hasChanged()) {
      responsecol=consolidatedResponse.getAddedCollection();
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("receive consolidated response change and size is "+responsecol.size());
      }
      sendAggResponse(responsecol);
    }
    Collection detailscol=null;
    if(detailedResponse.hasChanged()) {
      detailscol=detailedResponse.getAddedCollection();
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("receive Details Drill Down Query and size  "+ detailscol.size());
      }
      processDetailsResponseQuery(detailscol);
    }
    Collection idmefEventCollection=null;
    if(idmefEventResponse.hasChanged()){
      idmefEventCollection=idmefEventResponse.getAddedCollection();
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("receive Events/consolidated response and size is "+idmefEventCollection.size());
      }
      processIdmefEvent(idmefEventCollection);
    }

  }

  public void processIdmefEvent(Collection idmefEventCollection) {
    if(idmefEventCollection==null) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New IDMEF Collection  is NULL  :"+myAddress.toString() );
      } 
      return; 
    }
    if(idmefEventCollection.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New IDMEF Collection is empty  :"+myAddress.toString() );
      } 
      return; 
    }
    Map map=new Hashtable();
    Iterator iter=idmefEventCollection.iterator();
    Event event=null;
    RemoteConsolidatedEvent remoteEvent=null;
    UID originatorUID=null;
    List list=null;
    Object o;
    while(iter.hasNext()){
      o=iter.next();
      if(o instanceof Event) {
        event=(Event)o;
        originatorUID=DrillDownUtils.getUID(event.getEvent(),DrillDownQueryConstants.ORIGINATORS_UID);
        if(originatorUID!=null) {
          if(map.containsKey(originatorUID)){
            list=(List)map.get(originatorUID);
            list.add(event);
            map.put(originatorUID,list);
          }
          else {
            list=new ArrayList();
            list.add(event);
            map.put(originatorUID,list);
          }
        }
      }
      if(o instanceof RemoteConsolidatedEvent) {
        remoteEvent=(RemoteConsolidatedEvent)o;
        originatorUID=DrillDownUtils.getUID(remoteEvent.getEvent(),DrillDownQueryConstants.ORIGINATORS_UID);
        if(originatorUID!=null) {
          if(map.containsKey(originatorUID)){
            list=(List)map.get(originatorUID);
            list.add(createConsolidatedEvent(remoteEvent));
            map.put(originatorUID,list);
          }
          else {
            list=new ArrayList();
            list.add(createConsolidatedEvent(remoteEvent));
            map.put(originatorUID,list);
          }
        }
      }
    }// end of while
    Collection detailsQueryCollection=getBlackboardService().query(new DetailsDrillDownPredicate(myAddress));
    Set setkeys=map.keySet();
    Iterator keys=setkeys.iterator();
    UID key =null;
    CmrRelay relay=null;
    while(keys.hasNext()){
      list=null;
      key=(UID)keys.next();
      list=(List)map.get(key);
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Looking for CMR Relay with DetailsDrilldown query  and originator UID is :"+ key + 
                             " Total Details Drill Down Query present at agent "+ myAddress + " size :  "+ detailsQueryCollection.size() ); 
      }
      relay=getCmrRelayWithDetailsDrillDownQuery(key,detailsQueryCollection,true);
      if(relay==null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("No Details drill down query relay  present for parent UID :"+key.toString() );
        } 
        continue;
      }
      else {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Found CMR Relay with DetailsDrilldown query  and parent UID is :"+ key 
                               + " Relay uid is :"+ relay.getUID()); 
        }
      }
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Sending Response for Relay :"+ relay.getUID());
        Iterator i1=list.iterator();
        while(i1.hasNext()){
          o=i1.next();
          if(o instanceof Event){
            loggingService.debug(" Event is :"+ o.toString());
            
          }
          if(o instanceof RemoteConsolidatedEvent) {
            loggingService.debug(" Remote Consolidated Event is :"+ o.toString());
          }
        }
      }
      AggregatedResponse aggresponse=new AggregatedResponse(list); 
      relay.updateResponse(relay.getSource(),aggresponse);
      getBlackboardService().publishChange(relay);
    }
    
  }

  public CmrRelay getCmrRelayWithDetailsDrillDownQuery(UID givenUID, Collection detailsQueryCollection, boolean originator) {
    CmrRelay relay=null;
    DetailsDrillDownQuery detailsQuery=null;
    if(detailsQueryCollection==null) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("detailsQueryCollection  is NULL  :"+myAddress.toString() );
      } 
      return relay;  
    }
    if(detailsQueryCollection.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("detailsQueryCollection  is NULL  :"+myAddress.toString() );
      } 
      return relay;
    }
    Iterator iter=detailsQueryCollection.iterator();
    while(iter.hasNext()) {
      relay=(CmrRelay)iter.next();
      detailsQuery=(DetailsDrillDownQuery)relay.getContent();
      if(originator) {
        if(detailsQuery.getOriginatorUID().equals(givenUID)) {
          return relay;
        }
      }
      else {
        if(detailsQuery.getParentUID().equals(givenUID)) {
          return relay;
        } 
      }
      relay=null;
    }
    return relay;
  }
  public void processDetailsResponseQuery(Collection detailscol){
    if(detailscol.isEmpty()){
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New Detail Query is empty  :"+myAddress.toString() );
      } 
      return; 
    }
    Iterator iter=detailscol.iterator();
    CmrRelay relay=null;
    DetailsDrillDownQuery detailsQuery=null;
    CmrFactory factory=null;
   
    while(iter.hasNext()){
      relay=(CmrRelay)iter.next();
      detailsQuery=(DetailsDrillDownQuery)relay.getContent();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Looking for Events and Consolidated events with originator UID :"+detailsQuery.getOriginatorUID());
      }
      Collection detailedresponse=getBlackboardService().query(new EventsPredicate(detailsQuery.getOriginatorUID(),myAddress));
      if(detailedresponse.isEmpty()) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(" No response for DetailsDrillDownQuery  :"+detailsQuery.toString() );
        }
        continue;
      }
      List list=new ArrayList();
      Iterator detailsiter=detailedresponse.iterator();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Creating Response for Details DrillDown query :" +detailedresponse.size() ); 
      }
      Object obj=null;
      ConsolidatedEvent event=null;
      while(detailsiter.hasNext()){
        obj=detailsiter.next();
        if(obj instanceof RemoteConsolidatedEvent) {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug("Adding Remote Consolidated response from :" +((RemoteConsolidatedEvent)obj).getSource()); 
          }
          event= createConsolidatedEvent((RemoteConsolidatedEvent)obj);
          list.add(event );
        }
        else {
          list.add(obj);
        }
      }
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Creating Response for Details DrillDown query  and size of response is :" +list.size() ); 
      }
      AggregatedResponse aggresponse=new AggregatedResponse(list);
      
      relay.updateResponse(relay.getSource(),aggresponse);
      getBlackboardService().publishChange(relay);
    }
  }
  

  public void sendAggResponse(Collection responsecol) {
    
    if(responsecol.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New Consolidate response is empty  :"+myAddress.toString() );
      } 
      return;
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("Received New Consolidate response :"+myAddress.toString() + "Size of collection is :"+responsecol.size() );
    }
    Iterator iter=responsecol.iterator();
    CmrRelay detailsrelay=null;
    CmrRelay relay=null;
    ConsolidatedEvent consolidatedresult=null;
    UID parentuid=null;
    UID originatoruid=null;
    Collection detailsQueryCollection=getBlackboardService().query(new DetailsDrillDownPredicate(myAddress));
    while(iter.hasNext()){
      consolidatedresult=(ConsolidatedEvent)iter.next();
      parentuid=consolidatedresult.getParentUID();
      originatoruid=consolidatedresult.getOriginatorUID();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Received Consolidated response to Update  "+ 
                             consolidatedresult.toString()+"\n"+
                             "parent id  "+parentuid +"\n"+
                             "Source :"+consolidatedresult.getSource() );
      }
      detailsrelay=getCmrRelayWithDetailsDrillDownQuery(originatoruid,detailsQueryCollection,true);
      relay=findCmrRelay(parentuid);
      List list=new ArrayList();
      list.add(createNewConsolidatedEvent(consolidatedresult));
      AggregatedResponse aggresponse=new AggregatedResponse(list);
      if(detailsrelay==null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("No Details DrillDown query Relay present for parent UID :"+parentuid.toString() );
          loggingService.debug("Updating AGG DRILL DOWN query relay  :");
        } 
      }
      else {
        detailsrelay.updateResponse(relay.getSource(),aggresponse);
        getBlackboardService().publishChange(detailsrelay);
        getBlackboardService().publishRemove(consolidatedresult);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Successfully published response for Deatils Drilldown query relay :"+detailsrelay); 
        } 
      }
      if(relay!=null) {
        relay.updateResponse(relay.getSource(),aggresponse);
        getBlackboardService().publishChange(relay);
        getBlackboardService().publishRemove(consolidatedresult);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Successfully published response for relay :"+relay );
          //loggingService.debug("Successfully removed ConsolidatedEvent "+consolidatedresult );
        }
      }
      else {
        loggingService.error("ERROR cannot  find receive Agg relay  :"+ parentuid);
      }
        
    }
     
  } 
  
  public CmrRelay findCmrRelay(UID key) {
    CmrRelay relay = null;
    final UID fKey = key;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof CmrRelay) {
            CmrRelay relay = (CmrRelay)o;
            return ((relay.getUID().equals(fKey)) &&
                    (relay.getContent() instanceof AggregationDrillDownQuery));
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      relay = (CmrRelay)relays.iterator().next();
    }
    return relay;
  } 
   
  public ConsolidatedEvent createNewConsolidatedEvent(ConsolidatedEvent event) {
    ConsolidatedEvent newConsolidateEvent=null;
    CmrFactory factory=null;
    if(domainService!=null) {
      factory=(CmrFactory)domainService.getFactory("cmr");
    } 
    if(factory==null || event==null) {
      return newConsolidateEvent;
    }
    newConsolidateEvent= factory.newConsolidatedEvent(event);
    return newConsolidateEvent;
  }
}
