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
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.CompleteEvents;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.RemoteConsolidatedEvent;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
public class MnRAggSendCompleteEventPlugin extends MnRAggQueryBase {

  private IncrementalSubscription completeEventsRequest;
  private IncrementalSubscription removedCompleteEventsRequest;

  class NewCompleteEventPredicate implements  UnaryPredicate{
    private MessageAddress agentAddress;
    public  NewCompleteEventPredicate(MessageAddress address){
      agentAddress=address;
    }
    public boolean execute(Object o) {
      boolean ret = false;
      CmrRelay cmrRelay=null;
      if (o instanceof CmrRelay ) {
        cmrRelay=(CmrRelay)o;
        if((!(cmrRelay.getSource().equals(agentAddress)))&&
           (cmrRelay.getContent() instanceof CompleteEvents) &&
           (cmrRelay.getResponse()==null)){
          return true;
        }
      }
      return ret;
    }
  }

  class CompleteEventPredicate implements  UnaryPredicate{
    private MessageAddress agentAddress;
    public  CompleteEventPredicate(MessageAddress address){
      agentAddress=address;
    }
    public boolean execute(Object o) {
      boolean ret = false;
      CmrRelay cmrRelay=null;
      if (o instanceof CmrRelay ) {
        cmrRelay=(CmrRelay)o;
        if((!(cmrRelay.getSource().equals(agentAddress)))&&
           (cmrRelay.getContent() instanceof CompleteEvents)){
          return true;
        }
      }
      return ret;
    }
  }
  
  protected synchronized void setupSubscriptions() {
    super.setupSubscriptions();
    removedCompleteEventsRequest= (IncrementalSubscription)getBlackboardService().
      subscribe(new CompleteEventPredicate(myAddress));
    completeEventsRequest= (IncrementalSubscription)getBlackboardService().
      subscribe(new NewCompleteEventPredicate(myAddress));
  }
  
  protected synchronized void execute() {
    Collection newAllevents =null;
    Collection removedAllEventsRequest =null;
    if(completeEventsRequest.hasChanged()) {
      newAllevents=completeEventsRequest.getAddedCollection();
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("Received request for All events after SecurityConsole crash size of request : "+newAllevents.size());
      }
      sendAllEvents(newAllevents);
    }
    if(removedCompleteEventsRequest.hasChanged()){
      removedAllEventsRequest=removedCompleteEventsRequest.getRemovedCollection();
      if(removedAllEventsRequest.size()>0) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Remote  CompleteEvents  relay has been removed REMOTE RELAY REMOVED SIZE  ----"
                               +removedAllEventsRequest.size());
        }
        removeCompleteEventRequest(removedAllEventsRequest);
      }
    }
    
  }
  public void sendAllEvents (Collection requestCollection) {
    if(requestCollection.isEmpty()){
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("New Complete Events Query is empty  :"+myAddress.toString() );
      } 
      return; 
    }
    Iterator iter=requestCollection.iterator();
    CmrRelay relay=null;
    CompleteEvents allevents =null;
     
    while(iter.hasNext()){
      relay=(CmrRelay)iter.next();
      allevents=(CompleteEvents)relay.getContent();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Looking for Events and Consolidated events with originator UID :"+allevents.getOriginatorUID());
      }
      Collection detailedresponse=getBlackboardService().query(new EventsPredicate(allevents.getOriginatorUID(),myAddress));
      if(detailedresponse.isEmpty()) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(" No response for Complete Events Query  :"+allevents.toString() );
        }
        continue;
      }
      List list=new ArrayList();
      Iterator detailsiter=detailedresponse.iterator();
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Creating Response for Complete Events Query :" +detailedresponse.size() ); 
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
        loggingService.debug("Creating Response for  Complete Events Query and size of response is :" +list.size() ); 
      }
      AggregatedResponse aggresponse=new AggregatedResponse(list);
      relay.updateResponse(relay.getSource(),aggresponse);
      getBlackboardService().publishChange(relay);
    }
    
  }
  
  public void removeCompleteEventRequest(Collection removedRelays) {
    
  }
}
