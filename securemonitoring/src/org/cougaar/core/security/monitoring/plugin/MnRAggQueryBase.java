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



//Cougaar core  
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.AggQueryMapping;
import org.cougaar.core.security.monitoring.blackboard.AggQueryResult;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.RemoteConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.SensorAggregationDrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.AggregatedResponse;
import org.cougaar.core.security.monitoring.util.DrillDownUtils;
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
import java.util.Iterator;
import java.util.Set;
import java.util.List;


class AggQueryMappingPredicate implements UnaryPredicate {

  public boolean execute(Object o) {
    if( o instanceof AggQueryMapping){
      return true;
    }
    return false;
  }
  
}

class EventsPredicate implements  UnaryPredicate{
  private UID  originator_uid;
  public  EventsPredicate(UID uid,MessageAddress address){
    originator_uid=uid;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    RemoteConsolidatedEvent consolidatedEvent=null;
    Event event=null;
    if (o instanceof RemoteConsolidatedEvent ) {
      consolidatedEvent=(RemoteConsolidatedEvent)o;
      return DrillDownUtils.matchOriginatorUID(consolidatedEvent.getEvent(),originator_uid);
    }
    if(o instanceof Event ) {
      event=(Event)o;
      return DrillDownUtils.matchOriginatorUID(event.getEvent(),originator_uid);
    }
    return ret;
  }
}

public abstract class MnRAggQueryBase extends QueryBase{
  
  public ConsolidatedEvent createConsolidatedEvent(RemoteConsolidatedEvent event) {
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
  
  protected AggQueryMapping findAggQueryMappingFromBB(UID givenUID, Collection aggQueryMappingCol ) {
    AggQueryMapping aggQuerymapping=null;
    ArrayList queryList=null;
    AggQueryResult result=null;
    
    if(aggQueryMappingCol.isEmpty()) {
      return aggQuerymapping;
    }
    Iterator iter=aggQueryMappingCol.iterator();
    while(iter.hasNext()) {
      aggQuerymapping=(AggQueryMapping)iter.next();
      synchronized(aggQuerymapping){
        if(aggQuerymapping.getParentQueryUID().equals(givenUID)){
          return aggQuerymapping;
        }
        else {
          queryList=aggQuerymapping.getQueryList();
          if(queryList==null) {
            continue;
          }
          for(int i=0;i<queryList.size();i++) {
            result=(AggQueryResult)queryList.get(i);
            if(result.getUID().equals(givenUID)) {
              return aggQuerymapping;
            }
          }// end of for
        }// end else
      }
    }//end of while
    return null;
  } 
  
  protected Object findObject(UID uid) {
    Object queryObject = null;
    final UID fKey = uid;
    Collection relays = getBlackboardService().query( new UnaryPredicate() {
        public boolean execute(Object o) {
          SensorAggregationDrillDownQuery  sensorquery=null;
          if ((o instanceof CmrRelay)||( o instanceof SensorAggregationDrillDownQuery))  {
            if(o instanceof CmrRelay) {
              CmrRelay relay = (CmrRelay)o;
              return ((relay.getUID().equals(fKey)) &&
                      (relay.getContent() instanceof DrillDownQuery ));
            }
            if( o instanceof SensorAggregationDrillDownQuery) {
              sensorquery=(SensorAggregationDrillDownQuery)o;
              return(sensorquery.getUID().equals(fKey));
            }
          }
          return false;
        }
      });
    if(!relays.isEmpty()) {
      queryObject = relays.iterator().next();
    }
    return queryObject;
    
  } 

  public void publishResponse(Collection response, CmrRelay relay ){
    List list=new ArrayList();
    Iterator detailsiter=response.iterator();
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
      loggingService.debug("Creating Response for  Query and size of response is :" +list.size() ); 
    }
    AggregatedResponse aggresponse=new AggregatedResponse(list);
    relay.updateResponse(relay.getSource(),aggresponse);
    getBlackboardService().publishChange(relay);
  }
}
