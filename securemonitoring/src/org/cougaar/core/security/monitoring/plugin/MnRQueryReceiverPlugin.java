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
//import org.cougaar.core.service.LoggingService;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.CapabilitiesObject;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.OutStandingQuery;
import org.cougaar.core.security.monitoring.blackboard.QueryMapping;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

/*
  Predicate to get CMR Relay with new MRAgentLookUp query 
*/
class NewRemoteQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  public NewRemoteQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress)) &&
             ((relay.getContent() instanceof MRAgentLookUp) &&
              (relay.getResponse()==null)));
    }
    return ret;
  }
}
/*
  Predicate to get CMR Relay with new MRAgentLookUp query published locally  
*/
class NewLocalQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  public NewLocalQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = (((relay.getSource().equals(myAddress))&& ((relay.getTarget()!=null) &&(relay.getTarget().equals(myAddress) )))
             &&((relay.getContent() instanceof MRAgentLookUp) &&
                (relay.getResponse()==null)));
    }
    return ret;
  }
}
/*
  Predicate to get all Remote CMRRelay with MRAgentLookUp query 

*/
class RemoteQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  
  public RemoteQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((!relay.getSource().equals(myAddress))&&
             (relay.getContent() instanceof MRAgentLookUp)) ;
    }
    return ret;
  }
}

class AllQueryRelayPredicate implements  UnaryPredicate{
   MessageAddress myAddress;
  public AllQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
   public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      if(relay.getContent() instanceof MRAgentLookUp) {
        if(relay.getTargets()!=null && relay.getTargets().contains(myAddress)) {
          ret=true;
        }
        if(!relay.getSource().equals(myAddress)){
          ret=true;
        }
      }
    }
    return ret;
   }
}

class LocalQueryRelayPredicate implements  UnaryPredicate{
  MessageAddress myAddress;
  public LocalQueryRelayPredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((relay.getSource().equals(myAddress))&&
             (relay.getContent() instanceof MRAgentLookUp)) ;
    }
    return ret;
  }
}
/*
  Predicate to get All Query Mapping Object from BB
*/
class QueryMappingPredicate implements UnaryPredicate{
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof  QueryMapping ) {
      return true;
    }
    return ret;
  }
}


public class MnRQueryReceiverPlugin extends MnRQueryBase {
  
  private IncrementalSubscription capabilitiesobject;
  private IncrementalSubscription newRemoteQueryRelays;
  private IncrementalSubscription newLocalQueryRelays;
  private IncrementalSubscription remoteQueryRelays;
  private CapabilitiesObject      _capabilities;
  private ThreadService threadService=null;
  private final Map latestCallBack = Collections.synchronizedMap(new HashMap());
  
  // private String param;
  private boolean root = false;
  private String myRole = null;
  
  public void setParameter(Object o){
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }
     
    List l = (List) o;
    Iterator iter = l.iterator();
    String param=null; ;
    param = (String)iter.next();
    if(param.equalsIgnoreCase("root")){
      root = true;
    }
  }
  
  protected void setupSubscriptions() {
    super.setupSubscriptions(); 
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("setupSubscriptions of MnRQueryReceiverPlugin " +
                           "called :" + myAddress);
    }
    
    capabilitiesobject= (IncrementalSubscription)
      getBlackboardService().subscribe(new CapabilitiesObjectPredicate());

    newRemoteQueryRelays =(IncrementalSubscription) getBlackboardService().
      subscribe(new NewRemoteQueryRelayPredicate(myAddress));

    newLocalQueryRelays =(IncrementalSubscription) getBlackboardService().
      subscribe(new NewLocalQueryRelayPredicate(myAddress));
    
    remoteQueryRelays = (IncrementalSubscription)getBlackboardService().
      subscribe(new RemoteQueryRelayPredicate(myAddress));
    
    if (loggingService.isDebugEnabled()) {
      if (amIRoot()) {
        loggingService.debug("security community set as ROOT");
      }
    }
  }

  protected synchronized void execute () {
    if (loggingService.isDebugEnabled()) {
      loggingService.debug(myAddress + "MnRQueryReceiver execute().....");
    }
    CapabilitiesObject capabilities=null;
    Collection capabilitiesCollection;
    Collection newRemoteQueryCollection;
    Collection newLocalQueryCollection;
    Collection removedRemoteQueryCol;
    boolean removedRelays=false;
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    /*
      Check if remote relays has changed . If it has changed then we are interested in removed
      relays so that we can do our part of clean up
      
    */

    if((_capabilities!=null) &&(isRootReady()) && (amIRoot())){
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(myAddress + " _capabilities is not null so have to process all persistent queries "); 
      }
      processPersistantQueries(_capabilities, false);
      _capabilities=null;
    }
    if(remoteQueryRelays.hasChanged()) {
      removedRemoteQueryCol=remoteQueryRelays.getRemovedCollection();
      if(!removedRemoteQueryCol.isEmpty()) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(myAddress + " REMOTE RELAY Remove Notification in MnRQueryReceiver size of removed relay "+removedRemoteQueryCol.size() );
        }
        removedRelays=true;
        removeRelays(removedRemoteQueryCol,queryMappingCollection);
      }
    }
    
    if(capabilitiesobject.hasChanged()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(myAddress + " Sensor Registration HAS CHANGED  in MnRQueryReceiver ----");
      }
      capabilitiesCollection=capabilitiesobject.getChangedCollection();
      if (!capabilitiesCollection.isEmpty()) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(myAddress +" Sensor Registration HAS CHANGED  in MnRQueryReceiver and changed collection is not empty ");
        }
        capabilities = (CapabilitiesObject)capabilitiesCollection.iterator().next();
        if(!isRootReady()) {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug(myAddress + " Sensor Registration HAS CHANGED Root is not READY so processing only locally published persistent Query in MnRQueryReceiver");
          }
          processPersistantQueries(capabilities, true);
          _capabilities=capabilities;
        }
        else {
          if(amIRoot()) {
            if(_capabilities!=null) {
              _capabilities=null;
            }
            if (loggingService.isDebugEnabled()) {
              loggingService.debug(myAddress + " Sensor Registration HAS CHANGED Root is READY & I'M ROOT in MnRQueryReceiver");
              loggingService.debug(myAddress + " Processing remote persistent query ");
            }
            /*
              Since I'm the root security manager i should process both local as well as remote queries 
             */
            processPersistantQueries(capabilities,false);
          }
          else {
            processPersistantQueries(capabilities,true);
          }
        }
      }
      else {
        if( loggingService.isInfoEnabled()){
          loggingService.info(myAddress + " Registration has changed but query to bb returned empty collection:");
        }
      }
    }
    capabilitiesCollection=capabilitiesobject.getCollection();
    if(capabilitiesCollection.isEmpty()){
      if(loggingService.isWarnEnabled()){
        loggingService.warn(myAddress + " Query to BB for Sensor registration data returned empty collection "); 
      }
      return;
    }
    capabilities=(CapabilitiesObject)capabilitiesCollection.iterator().next();
    if(newRemoteQueryRelays.hasChanged()){
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(myAddress + " newRemote queryRelays HAS CHANGED ----");
      }
      newRemoteQueryCollection=newRemoteQueryRelays.getAddedCollection();
      processNewQueries(capabilities,newRemoteQueryCollection);
    }
    
    /*
      Check if new query is published locally and processes it
    */
    if(newLocalQueryRelays.hasChanged()){
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(myAddress + " new Local queryRelays HAS CHANGED ----");
      }
      newLocalQueryCollection=newLocalQueryRelays.getAddedCollection(); 
      processNewQueries(capabilities,newLocalQueryCollection);
    } 
     
  }

  private void processNewQueries(final CapabilitiesObject capabilities, 
                                 final Collection newQueries) {
    QueryMapping mapping;
    Iterator iter=newQueries.iterator();
    MRAgentLookUp agentlookupquery;
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    while(iter.hasNext()) {
      mapping=null;
      final CmrRelay relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        loggingService.warn("Contents of the relay is null:"+relay.toString());
        continue;
      }
      mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(mapping==null) {
        FindAgentCallback fac = new FindAgentCallback() {
            public void execute(Collection agents) {
              if (loggingService.isDebugEnabled()) {
                loggingService.debug("Found response for manager and size " +
                                     "of response :" + agents.size() );
              }
              if(latestCallBack.containsKey(relay.getUID())) {
                FindAgentCallback callback=(FindAgentCallback )latestCallBack.get(relay.getUID());
                if(this.equals(callback)) {
                  createSubQuery(capabilities, agents, relay);
                }
                else {
                  if (loggingService.isDebugEnabled()) {
                    loggingService.debug(" Ignoring  call back for realy uid "+ relay.getUID() +
                                         " callback id is stale "+ this.toString() );
                  }
                }
              }
              else {
                if (loggingService.isDebugEnabled()) {
                  loggingService.debug(" relay uid is not in list of active call back list" +relay.getUID());  
                }
              }
            }
          };
        if (loggingService.isDebugEnabled()) {
          loggingService.debug( myAddress +" Adding latest callback id for relay "+relay.getUID() + " callback id is :"+fac );  
        }
        latestCallBack.put(relay.getUID(),fac);        
        findAgent(agentlookupquery, capabilities, false, fac);
      }
      else {
        loggingService.error(" There should have been No Mapping object for :"+relay.getUID());
      }
    }// end of While
  }// end  processNewQueries

  private void processPersistantQueries(final CapabilitiesObject capabilities, boolean local) {
    QueryMapping mapping;
    MRAgentLookUp agentlookupquery;
    CmrRelay relay;
    Collection relaystoProcess=null;
    if(local){
      relaystoProcess= getBlackboardService().query(new LocalQueryRelayPredicate(myAddress));
      if(loggingService.isDebugEnabled()){
        loggingService.debug(" size LocalQueryRelayPredicate is :"+ relaystoProcess.size());
      }
    }
    else {
      relaystoProcess=getBlackboardService().query(new AllQueryRelayPredicate(myAddress));
      if(loggingService.isDebugEnabled()){
        loggingService.debug(" size AllQueryRelayPredicate is :"+ relaystoProcess.size());
      }
    }
    
    if(relaystoProcess.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        if(local) {
          loggingService.debug(" Query to BB for Local MRAgentLookup returned EMPTY Collection");
        }
        else {
          loggingService.debug(" Query to BB for Remote MRAgentLookup returned EMPTY Collection");
        }
      }
      return;
    }
    Collection queryMappingCollection=getBlackboardService().query(new QueryMappingPredicate());
    Iterator iter=relaystoProcess.iterator();
    // removing mapping for query relays relay 
    while(iter.hasNext()){
      mapping=null;
      relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        loggingService.warn("Contents of the relay is null:"+relay.toString());
        continue;
      }
      if(agentlookupquery.updates) {
        if(latestCallBack.containsKey(relay.getUID())) {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug("REMOVING all agent call back for "+relay.getUID());
          }
          latestCallBack.remove(relay.getUID());
        }
        mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
        if(mapping!=null) {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug("REMOVING OLD MAPPING"+mapping.toString());
          }
          removeRelay(mapping,null);
          getBlackboardService().publishRemove(mapping);
        }
      }
    }
    // publish new mapping for relays 
    iter=relaystoProcess.iterator();
    while(iter.hasNext()) {
      mapping=null;
      relay = (CmrRelay)iter.next();
      agentlookupquery=(MRAgentLookUp)relay.getContent();
      if(agentlookupquery==null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.warn("Contents of the relay is null:"+relay.toString());
        }
        continue;
      }
      if(agentlookupquery.updates) {
        final CmrRelay fRelay = relay;
        FindAgentCallback fac = new FindAgentCallback() {
            public void execute(Collection agents) {
              if (loggingService.isDebugEnabled()) {
                loggingService.debug(" Process Persitent Query Found response for manager and size " +
                                     "of response :" + agents.size() );
              }
              if(latestCallBack.containsKey(fRelay.getUID())) {
                FindAgentCallback callback=(FindAgentCallback )latestCallBack.get(fRelay.getUID());
                if(this.equals(callback)) {
                  createSubQuery(capabilities, agents, fRelay);
                }
                else {
                  if (loggingService.isDebugEnabled()) {
                    loggingService.debug(" Process Persitent Query Ignoring  call back for realy uid "+ fRelay.getUID() +
                                         " callback id is stale "+ this.toString() );
                  }
                }
              }
              else {
                if (loggingService.isDebugEnabled()) {
                  loggingService.debug("Process Persitent Query  relay uid is not in list of active call back list" +fRelay.getUID());  
                }
              }
            }
          };
        if (loggingService.isDebugEnabled()) {
          loggingService.debug( myAddress +" Process Persitent Query Adding latest callback id for relay "+fRelay.getUID() + " callback id is :"+fac );  
        }
        latestCallBack.put(fRelay.getUID(),fac); 
        findAgent(agentlookupquery, capabilities, false, fac);
      }// end agentlookupquery.updates
    }//end while()
  }  
  
  private void createSubQuery(CapabilitiesObject capabilities, 
                              Collection subManager, CmrRelay relay) {
    QueryMapping mapping;
    MRAgentLookUp agentlookupquery=null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if(relay!=null) {
      agentlookupquery=(MRAgentLookUp)relay.getContent();
    }
    else {
      loggingService.error("relay is null in createSub query ");
    }
    if(!subManager.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("MnRQueryReceiver plugin  Creating new Sub Query relays:"
                             + myAddress.toString());
      }
      Iterator response_iterator=subManager.iterator();
      String key=null;
      RegistrationAlert reg;
      MessageAddress dest_address;
      ArrayList relay_uid_list=new ArrayList();
      //boolean modified=false;
      if (loggingService.isDebugEnabled()) {
        loggingService.debug("Going through list of agents found in Query receiver plugin  :");
      }
      while(response_iterator.hasNext()) {
        key=(String)response_iterator.next();
        reg=(RegistrationAlert)capabilities.get(key);
        dest_address=MessageAddress.getMessageAddress(key);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("Creators Address for Sub Query relay is :"
                               + myAddress.toString());
          loggingService.debug("Destination address for Sub Query relay is :"
                               +dest_address.toString());
        }
        CmrRelay forwardedrelay = null;
        forwardedrelay = factory.newCmrRelay(agentlookupquery, dest_address);
        relay_uid_list.add(new OutStandingQuery(forwardedrelay.getUID()));
        publishToBB(forwardedrelay);
        if (loggingService.isDebugEnabled()) {
          loggingService.debug(" Sub Query relay is :"
                               +forwardedrelay.toString());
        }
      }
      mapping=new QueryMapping(relay.getUID(), relay_uid_list);
      publishToBB(mapping);
    }
    else {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" No sub Manager are present with this capabilities :");
        loggingService.debug("Creating an empty query mapping for Parent relay  :"+relay.getUID() );
      }
      mapping=new QueryMapping(relay.getUID(), null);
      publishToBB(mapping);
    }
  }
                                                         
  public void publishToBB(Object data ){
    final Object obj=data;
    if(threadService==null) {
      threadService = (ThreadService)
        getServiceBroker().getService(this,ThreadService.class, null); 
    }
    Schedulable subqueryThread = threadService.getThread(this, new Runnable( ) {
        public void run(){
          getBlackboardService().openTransaction();
          try {
            getBlackboardService().publishAdd(obj);
          } catch (Exception e) {
            loggingService.error("Exception when publishing " + obj, e);
          } finally {
            getBlackboardService().closeTransactionDontReset();      
          }
        }
      },"QueryMappingPublisherThread");
    subqueryThread.start();
  } 
  
  
  private void removeRelays(Collection removedRelays,Collection queryMappingCollection  ) {
    CmrRelay relay;
    QueryMapping mapping;
    Iterator iter=removedRelays.iterator();
    if(queryMappingCollection.isEmpty()) {
      if (loggingService.isDebugEnabled()) {
        loggingService.debug(" queryMappingCollection in removeRelays is EMPTY");
      }
    }
    if (loggingService.isDebugEnabled()) {
      loggingService.debug("SIZE OF queryMappingCollection:"+queryMappingCollection.size());
    }
    while(iter.hasNext()) {
      mapping=null;
      relay = (CmrRelay)iter.next();
      mapping=findQueryMappingFromBB(relay.getUID(),queryMappingCollection) ;
      if(mapping!=null) {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING MAPPING :"+mapping.toString());
        }
        
        if(isRelayQueryOriginator(relay.getUID(),queryMappingCollection)) {
          removeRelay(mapping,null);
        }
        else {
          if (loggingService.isDebugEnabled()) {
            loggingService.debug(" Removing of one relay from Mapping object should not happen ");
          }
          removeRelay(mapping,relay.getUID());
        }
      }
      else {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING MAPPING COULD not find mapping for Relay :"+relay.getUID());
        }
      }
      
    }// end while
  }// end removeRelays
  /*
    removes all relay specified in the QueryMapping unless second parameter relayuid is specified 
    if second parameter relayuid ids not null it will remove onlt that realy 
  */
  private void removeRelay(QueryMapping mapping, UID relayuid) {
    if(mapping==null) {
      return;
    } 
    ArrayList list=mapping.getQueryList();
    if((list==null)||(list.isEmpty())){
      return;
    }
    OutStandingQuery outstandingquery;
    CmrRelay relay=null;
    for(int i=0;i<list.size();i++) {
      outstandingquery=(OutStandingQuery)list.get(i);
      relay=findCmrRelay(outstandingquery.getUID());
      if(relay!=null) {
        if(relayuid!=null) {
          if(relay.getUID().equals(relayuid)) {
            getBlackboardService().publishRemove(relay); 
          }
        }
        else {
          getBlackboardService().publishRemove(relay);
        }
      }
      else {
        if (loggingService.isDebugEnabled()) {
          loggingService.debug("REMOVING Relay COULD not find mapping for Relay :"+outstandingquery.getUID()); 
        }
        
      }
    }// end of For loop
  }
}
