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
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.AggQueryMapping;
import org.cougaar.core.security.monitoring.blackboard.AggQueryResult;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.MnRAggRateCalculator;
import org.cougaar.core.security.monitoring.blackboard.SensorAggregationDrillDownQuery;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.AggregationResultSet;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.util.XmlUtils;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;


class AggCapabilitiesPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CapabilitiesObject ) {
      return true;
    }
    return ret;
  }
}
class PersistantAggQueryRelayPredicate implements  UnaryPredicate{
  
  MessageAddress myAddress;
  
  public PersistantAggQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      DrillDownQuery query=null;
      if((!relay.getSource().equals(myAddress)) &&((relay.getContent() instanceof DrillDownQuery) )) {
        query=(DrillDownQuery) relay.getContent();
        ret= query.isPersistent();      
      }
    }
    return ret;
  }
  
}
class NewAggQueryRelayPredicate implements  UnaryPredicate{
  
  MessageAddress myAddress;
  
  public NewAggQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress)) &&(
               (relay.getContent() instanceof DrillDownQuery) &&
               (relay.getResponse()==null)));
    }
    return ret;
  }
}

class RemoteAggQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  
  public RemoteAggQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress))&&
             (relay.getContent() instanceof DrillDownQuery)
        ) ;
    }
    return ret;
  }
}

public class MnRAggQueryReceiverPlugin extends MnRAggQueryBase  {

  private IncrementalSubscription capabilities;
  private IncrementalSubscription newAggQueryRelays;
  private IncrementalSubscription remoteAggQueryRelays;
  private CapabilitiesObject      _capabilities;
  UIDService uidService=null;
  SensorInfo _sensorInfo=null;


  protected void setupSubscriptions() {
    super.setupSubscriptions();    
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin " +
                           "called :" + myAddress);
    }
   
    capabilities = (IncrementalSubscription)getBlackboardService().
      subscribe (new AggCapabilitiesPredicate());
   
    newAggQueryRelays=(IncrementalSubscription)getBlackboardService().
      subscribe(new  NewAggQueryRelayPredicate(myAddress));
    remoteAggQueryRelays=(IncrementalSubscription)getBlackboardService().
      subscribe(new  RemoteAggQueryRelayPredicate(myAddress));
    uidService=(UIDService) 
      getServiceBroker().getService(this,UIDService.class,null);
    if (uidService==null) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Unable to get UIDService in " +
                             "processNewAggQuery");
      }
    }   
  }
  
  protected void execute () {
    Collection removedRemoteAggQuery=null;
    Collection capabilitiesCollection=null;
    Collection newRemoteAggQuery=null;
    CapabilitiesObject capabilitiesTable=null;
   
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(myAddress + "MnRAggQueryReceiverPlugin  execute().....");
    }
    /*
      Removing all the remote relays that have been deleted
    */
    if(remoteAggQueryRelays.hasChanged()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("remote Agg Query relay has changed");
      }
      removedRemoteAggQuery=remoteAggQueryRelays.getRemovedCollection();
      if(removedRemoteAggQuery.size()>0) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Remote  Agg Query relay has been removed REMOTE RELAY REMOVED SIZE  ----"
                               +removedRemoteAggQuery.size());
        }
        processRemoveAggQuery(removedRemoteAggQuery);
      }
    }
    /*
      New Sensor have registered. This change will remove old query relays and publishing new 
      query relays only at agent with role "Root"
    */
    if(capabilities.hasChanged()) {
      capabilitiesCollection=capabilities.getChangedCollection();
      if (!capabilitiesCollection.isEmpty()) {
        if (isRootReady()) {
          if (_capabilities != null) {
            if (amIRoot()) {
              processPersistentQueries(_capabilities);
            }
            _capabilities = null;
          }
          if(amIRoot()) {
            if (loggingService.isDebugEnabled()) {
              loggingService.debug("MnRAggQueryReceiverPlugin  Capabilities " +
                                   " HAS CHANGED ----");
            }
            capabilitiesTable=(CapabilitiesObject)
              capabilitiesCollection.iterator().next();
            processPersistentQueries(capabilitiesTable);
            return;
          }
        } else {
          // root is not ready... store for later
          _capabilities = (CapabilitiesObject)
            capabilitiesCollection.iterator().next();
          return;
        }
      }
    }
    else {
      capabilitiesCollection=capabilities.getCollection();
      Iterator i=capabilitiesCollection.iterator();
      if(i.hasNext()) {
        capabilitiesTable=(CapabilitiesObject) i.next();
      }
    }

    if(newAggQueryRelays.hasChanged()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" Remote Agg query Relays HAS CHANGED ----");
      }
      newRemoteAggQuery=newAggQueryRelays.getAddedCollection();
      processNewAggQuery(newRemoteAggQuery,capabilitiesTable);
    }
  }



  public void processRemoveAggQuery(Collection removedQueries) {
    CmrRelay relay;
    AggQueryMapping aggmapping;
    Iterator iter=removedQueries.iterator();
    Collection queryMappingCollection=getBlackboardService().query(new AggQueryMappingPredicate());
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("SIZE OF queryMappingCollection:"+queryMappingCollection.size());
    }
    while(iter.hasNext()) {
      aggmapping=null;
      relay = (CmrRelay)iter.next();
      aggmapping=findAggQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(aggmapping!=null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING MAPPING :"+aggmapping.toString());
        }
        removeRelay(aggmapping);
      }
      else {
        loggingService.debug("REMOVING MAPPING COULD not find mapping for Relay :"+relay.getUID());
      }
    }
    
  }
  
  private void removeRelay (AggQueryMapping aggmapping) {
    if(aggmapping==null) {
      return;
    } 
    ArrayList list=aggmapping.getQueryList();
    if(list==null) {
      return;
    }
    if(list.isEmpty()) {
      return;
    }
   
    AggQueryResult subqueries;
    Object subrelay=null;
    for(int i=0;i<list.size();i++) {
      subqueries=(AggQueryResult)list.get(i);
      subrelay=findObject(subqueries.getUID());
      if(subrelay!=null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING subqueries  :"+subrelay.toString());
        }
        getBlackboardService().publishRemove(subrelay); 
      }
    }
    
  }



  public void processPersistentQueries(CapabilitiesObject capabilitiesTable) {
    Collection persistentQueryCol=getBlackboardService().query(new PersistantAggQueryRelayPredicate(myAddress));
    if(persistentQueryCol==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" No Persistent Agg Queries to process as Collection is NULL");
      }
    }
    if(persistentQueryCol.isEmpty()) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" No Persistent Agg Queries to process as Collection is Empty");
      }
    }
    Collection queryMappingCollection=getBlackboardService().query(new AggQueryMappingPredicate());
    Iterator iter=persistentQueryCol.iterator();
    CmrRelay relay=null;
    AggQueryMapping aggmapping;
    while(iter.hasNext()){
      relay=(CmrRelay)iter.next();
      aggmapping=findAggQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(aggmapping!=null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING MAPPING in processPersistentQueries   :"+aggmapping.toString());
        }
        removeRelay(aggmapping);
      }
      else {
        loggingService.debug("REMOVING MAPPING (processPersistentQueries)COULD not find mapping for Relay :"+relay.getUID());
      }
      publishNewAggSubQueries(relay,capabilitiesTable);
    }
    
    
  }

  public void publishNewAggSubQueries (CmrRelay queryrelay, CapabilitiesObject capabilitiesTable) {
    if(queryrelay==null || queryrelay.getContent()==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Relay or relay Content is NULL in publishNewAggSubQueries ");
      } 
    }
    ArrayList subQueries=new ArrayList();
    UID newUID=null;
    ThreadService ts=(ThreadService) getServiceBroker().getService(this, ThreadService.class, null);
    UIDService uidService=(UIDService) getServiceBroker().getService(this,UIDService.class,null);
    if(uidService==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Unable to get UIDService in publishNewAggSubQueries ");
      }
    }
    DrillDownQuery query=(DrillDownQuery)queryrelay.getContent();
    if(query.getOriginatorsUID()==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug("publishNewAggSubQueries Agg Query Relay DIRECTLY FROM SOURCE :"+queryrelay.getSource()); 
      }
      query.setOriginatorsUID(queryrelay.getUID());
      if(loggingService.isDebugEnabled()) {
        loggingService.debug("Setting originator UID : "+query.getOriginatorsUID() +" publishNewAggSubQueries Relay ID : "+queryrelay.getUID()); 
      }
    }
    MnRAggRateCalculator ratecalculator=(MnRAggRateCalculator)query.getAggregationType();
    Enumeration enumKeys=capabilitiesTable.keys();
    Vector alreadyPublished=new Vector();
    AggQueryMapping aggQueryMapping;
    RegistrationAlert regAlert=null;
    String key =null;
    while(enumKeys.hasMoreElements()) {
      key=(String)enumKeys.nextElement();
      regAlert= (RegistrationAlert)capabilitiesTable.get(key);
      if( loggingService.isDebugEnabled()) {
        loggingService.debug("key is : "+ key + "Registration type :"+ regAlert.getType() );
        loggingService.debug("Agent name from registration alert is  : "+ regAlert.getAgentName() ) ;
      }
      if((regAlert.getType().equals(IdmefMessageFactory.SensorType))){
        UID publishedUID=publishAggToSensor(regAlert,alreadyPublished,query);
        if(publishedUID!=null) {
          alreadyPublished.add(regAlert.getAgentName());
          subQueries.add(new AggQueryResult(publishedUID));
          if( loggingService.isDebugEnabled()) {
            loggingService.debug(" Published Sensor Agg Query in  processNewAggQuery to " +regAlert.getAgentName());
          }
        }
      }// end of  if((regAlert.getType().equals(IdmefMessageFactory.SensorType)))
      if(regAlert.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
        UID publishedUID=publishAggToMnrMgr(key,query);
        if(publishedUID!=null) {
          alreadyPublished.add(regAlert.getAgentName());
          subQueries.add(new AggQueryResult(publishedUID));
          if( loggingService.isDebugEnabled()) {
            loggingService.debug(" Published Agg Query to MnR Manager in  processNewAggQuery to " +key);
          }
        }
        
      }//end of  if(regAlert.getType().equals(IdmefMessageFactory.SecurityMgrType))
        
    }// end of while(enumkeys.hasMoreElements())
    aggQueryMapping=new AggQueryMapping(query.getOriginatorsUID(),queryrelay.getUID(),subQueries);
    getBlackboardService().publishAdd(aggQueryMapping);
    MnRAggRateCalculator newratecalculator=new MnRAggRateCalculator(ratecalculator);
    newratecalculator.setBlackboardService(getBlackboardService());
    newratecalculator.setLoggingService(loggingService);
    newratecalculator.setUID(queryrelay.getUID());
    newratecalculator.setDomainService(getDomainService());
    newratecalculator.setAddress(myAddress);
    if( loggingService.isDebugEnabled()) {
      loggingService.debug(" Setting rate window to  " +newratecalculator._timewindow);
    }
    ts.getThread(this, newratecalculator).schedule(
      0,(long)newratecalculator._timewindow);

  }
  
  public void processNewAggQuery(Collection newAggQuery, CapabilitiesObject capabilitiesTable) {
    CmrRelay queryrelay=null;
    Enumeration enumKeys=null;
    RegistrationAlert regAlert=null;
    DrillDownQuery query=null;
    if(capabilitiesTable==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Capabilities object is NULL in processNewAggQuery");
      }
      return;
    }
    
    if(capabilitiesTable.isEmpty()) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Capabilities object is EMPTY  in processNewAggQuery");
      }
      return;
    }
    if(newAggQuery.isEmpty()){
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" New Agg query Collection  EMPTY  in processNewAggQuery");
      }
      return;
    }
    UIDService uidService=(UIDService) getServiceBroker().getService(this,UIDService.class,null);
    if(uidService==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Unable to get UIDService in processNewAggQuery");
      }
    }
    Iterator iter=newAggQuery.iterator();
    String key=null;
    ArrayList subQueries=new ArrayList();
    UID newUID=null;
    ThreadService ts=(ThreadService) getServiceBroker().getService(this, ThreadService.class, null);
    while(iter.hasNext()) {
      queryrelay=(CmrRelay)iter.next();
      query=(DrillDownQuery)queryrelay.getContent();
      if(query.getOriginatorsUID()==null) {
        if( loggingService.isDebugEnabled()) {
          loggingService.debug("Received Agg Query Relay DIRECTLY FROM SOURCE :"+queryrelay.getSource()); 
        }
        query.setOriginatorsUID(queryrelay.getUID());
        if(loggingService.isDebugEnabled()) {
          loggingService.debug("Setting originator UID : "+query.getOriginatorsUID() +" Received Relay ID : "+queryrelay.getUID()); 
        }
      }
      MnRAggRateCalculator ratecalculator=(MnRAggRateCalculator)query.getAggregationType();
      enumKeys=capabilitiesTable.keys();
      Vector alreadyPublished=new Vector();
      AggQueryMapping aggQueryMapping;
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" RECEIVED RELAY in  processNewAggQuery");
      }
      while(enumKeys.hasMoreElements()) {
        key=(String)enumKeys.nextElement();
        regAlert= (RegistrationAlert)capabilitiesTable.get(key);
        if( loggingService.isDebugEnabled()) {
          loggingService.debug("key is : "+ key + "Registration type :"+ regAlert.getType() );
          loggingService.debug("Agent name from registration alert is  : "+ regAlert.getAgentName() ) ;
        }
        if((regAlert.getType().equals(IdmefMessageFactory.SensorType))){
          UID publishedUID=publishAggToSensor(regAlert,alreadyPublished,query);
          if(publishedUID!=null) {
            alreadyPublished.add(regAlert.getAgentName());
            subQueries.add(new AggQueryResult(publishedUID));
            if( loggingService.isDebugEnabled()) {
              loggingService.debug(" Published Sensor Agg Query in  processNewAggQuery to " +regAlert.getAgentName());
            }
          }
        }// end of  if((regAlert.getType().equals(IdmefMessageFactory.SensorType)))
        if(regAlert.getType().equals(IdmefMessageFactory.SecurityMgrType)) {
          UID publishedUID=publishAggToMnrMgr(key,query);
          if(publishedUID!=null) {
            alreadyPublished.add(regAlert.getAgentName());
            subQueries.add(new AggQueryResult(publishedUID));
          }

        }//end of  if(regAlert.getType().equals(IdmefMessageFactory.SecurityMgrType))
        
      }// end of while(enumkeys.hasMoreElements())
      aggQueryMapping=new AggQueryMapping(query.getOriginatorsUID(),queryrelay.getUID(),subQueries);
      getBlackboardService().publishAdd(aggQueryMapping);
      MnRAggRateCalculator newratecalculator=new MnRAggRateCalculator(ratecalculator);
      newratecalculator.setBlackboardService(getBlackboardService());
      newratecalculator.setLoggingService(loggingService);
      newratecalculator.setUID(queryrelay.getUID());
      newratecalculator.setDomainService(getDomainService());
      newratecalculator.setAddress(myAddress);
      ts.getThread(this, newratecalculator).schedule(
	0,(long)newratecalculator._timewindow);
    }// end of  while(iter.hasNext())
    
  }
  

  public UID publishAggToMnrMgr(String key,DrillDownQuery query){
    UID newUID=null;
    CmrRelay forwardedrelay = null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    
    if( loggingService.isDebugEnabled()) {
      loggingService.debug("Going to publish Agg query Relay to MnR manger :"+ key );
    }
    if( loggingService.isDebugEnabled()) {
      loggingService.debug("Received DrillQuery from some MnR Manager"+ query.getOriginatorsUID().toString());
    }
    forwardedrelay=factory.newDrillDownQueryRelay(query.getOriginatorsUID(),query.getAggQuery(),
                                                  query.getAggregationType(),query.wantDetails(), 
                                                  MessageAddress.getMessageAddress(key));
    newUID=forwardedrelay.getUID();
    getBlackboardService().publishAdd(forwardedrelay);
    if( loggingService.isDebugEnabled()) {
      loggingService.debug("Published Agg query to Mnr Manager with  UID :"+ newUID.toString() );
      loggingService.debug("Published Agg query to Mnr Manager with query is  :"+ forwardedrelay.toString() );
    }
    return newUID;
  }

  public UID publishAggToSensor(RegistrationAlert regAlert ,Vector alreadPublished,DrillDownQuery query ) {
    //boolean alreadyPublished=false;
    String aggQuery=null;
    AggregationQuery newaggQuery=null;
    UID newUID=null;
    SensorAggregationDrillDownQuery localQuery=null;
    if( loggingService.isDebugEnabled()) {
      loggingService.debug("Going to publish Agg query to sensor :"+ regAlert.getAgentName() );
    }
    if(!containsPublishedAgent(regAlert.getAgentName(),alreadPublished)){
      aggQuery=query.getAggQuery();
      localQuery=createAggregationQuery(aggQuery);
      if(localQuery==null) {
        if( loggingService.isDebugEnabled()) {
          loggingService.debug(" Cannot create New AggregationDrillDownQuery");
        }
        return null;
      }
      if(uidService!=null) {
        newUID=uidService.nextUID();
      }
      localQuery.setUID(newUID);
      newaggQuery=localQuery.getQuery();
      newaggQuery.addSourceCluster(regAlert.getAgentName());
      if( loggingService.isDebugEnabled()) {
        //loggingService.debug("Query spec is :"+ newaggQuery.getPredicateSpec());
        loggingService.debug("Aggent name where query is published is  :"+ regAlert.getAgentName()+ 
                             "uid is :" +localQuery.getUID() );
                             
      }
      //subQueries.add(new AggQueryResult(localQuery.getUID()));
      getBlackboardService().publishAdd(localQuery) ;
      //alreadPublished.add(regAlert.getAgentName());
      if( loggingService.isDebugEnabled()) {
        loggingService.debug("Published Agg query to Local sensor UID :"+ localQuery.getUID().toString() );
        //loggingService.debug("Published Agg query to Local sensor query is  :"+ localQuery.toString() );
      }
    }// end of if(!containsPublishedAgent(regAlert.getAgentName(),alreadPublished))
    else {
      return null;
    }
    return newUID;
  }

  public QueryResultAdapter createAggregationQuery(AggregationQuery query) {
    //SensorAggregationDrillDownQuery localQuery=null;
    QueryResultAdapter localQuery=null;
    if(query==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Cannot create New AggregationDrillDownQuery as AggregationQuery received is NULL ");
      }
      return  localQuery; 
    }
    AggregationQuery aq = new AggregationQuery(query.getType());
    aq.setName(query.getName());
    aq.setUpdateMethod(query.getUpdateMethod());
    ScriptSpec spec = query.getPredicateSpec();
    ScriptSpec spec1 = new ScriptSpec(spec.getType(), spec.getLanguage(), spec.getText());
    loggingService.debug(" Text in script spec is :"+  spec.getText());
    loggingService.debug("Format of script spec" +query.getFormatSpec().toXml());
    loggingService.debug("Predicate f script spec" +query.getPredicateSpec().toXml());
    aq.setPredicateSpec(spec1);
    aq.setFormatSpec(query.getFormatSpec());
    localQuery = new QueryResultAdapter(aq);
    localQuery.setResultSet(new AggregationResultSet());
    /*
      localQuery=new SensorAggregationDrillDownQuery(aq);
      localQuery=new SensorAggregationDrillDownQuery(query);
      localQuery.setResultSet(new AggregationResultSet());
    */
    return localQuery;
  }

  private SensorAggregationDrillDownQuery createAggregationQuery(String query) {
    SensorAggregationDrillDownQuery localQuery=null;
    if(query==null) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Cannot create New AggregationDrillDownQuery as AggregationQuery received is NULL ");
      }
      return  localQuery; 
    }
    AggregationQuery aq=null;
    try{
      aq= new AggregationQuery(XmlUtils.parse(query));
    }
    catch (java.io.IOException IOExp) {
      IOExp.printStackTrace();
      return localQuery;
    }
    catch(org.xml.sax.SAXException SaxExp) {
      SaxExp.printStackTrace();
      return localQuery;
    }
    localQuery = new SensorAggregationDrillDownQuery(aq);
    localQuery.setResultSet(new AggregationResultSet());
    return localQuery;
  }
  
  private String getAgentName(String sensorId) {
    String agentName=null;
    if(sensorId==null){
      if( loggingService.isDebugEnabled()) {
        loggingService.debug("WARN : Cannot get agent Name from sensor id as sensorId is NULL  ");
      }
      return agentName;
    }
    int index=sensorId.indexOf('/');
    if(index!=-1) {
      agentName=sensorId.substring(0,index);
    }
    return agentName;
  }


  
   

  private boolean containsPublishedAgent(String agentname,Vector publishedAgents){
    boolean published=false;
    if(publishedAgents.isEmpty()){
      return published;
    } 
    String agent=null;
    for(int i=0;i<publishedAgents.size();i++) {
      agent=(String)publishedAgents.elementAt(i);
      if(agent.equalsIgnoreCase(agentname)){
        published=true;
        return published;
      }
    }
    return published;
  }
  protected SensorInfo getSensorInfo() {
    if(_sensorInfo == null) {
      _sensorInfo = new MnRManagerSensor();  
    } 
    return _sensorInfo;
  }
  
  public class MnRManagerSensor implements SensorInfo {
    
    public String getName(){
      StringBuffer buff=new StringBuffer();
      buff.append("MnRMgr-"+myAddress.toString());
      return buff.toString();
    }
    
    public String getManufacturer(){
      return "Cougaar Software";
    }

    public String getModel(){
      return "Cougaar";
    }
    public String getVersion(){
      return "1.0";
    }
    public String getAnalyzerClass(){
      return "Security Mgr Analyzer";
    }
  }
  
} 
