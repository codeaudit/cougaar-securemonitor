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

// cougaar core classes
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.blackboard.MnRManager;
import org.cougaar.core.security.monitoring.blackboard.MnRManagerObject;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.service.community.Entity;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

/**
 * abstract sensor class that registers the capabilities of the sensor
 * two methods must be implemented in the subclass:
 *
 * getSensorInfo
 * getClassifications
 * agentIsTarget
 *
 * subclass setupSubscription must call super.setupSubscription inorder
 * for the registration to take place.
 */

class ManagerAgentPredicate implements UnaryPredicate{
   public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof MnRManager ) {
      return true;
    }
    return ret;
   }
}
public abstract class SensorPlugin extends ComponentPlugin {

  private MessageAddress myAddress;
  protected MessageAddress myManagerAddress;

  /**
   * method to obtain the sensor info for the concrete class
   */
  protected abstract SensorInfo getSensorInfo();
  /**
   * method to obtain the list of classification the sensor is capable of
   * detecting
   */
  protected abstract String []getClassifications();
  /**
   * method to determine if the agent, the plugin is running in, is the target
   * of attacks
   */
  protected abstract boolean agentIsTarget();
  /**
   * method to determine if the agent, the plugin is running in, is the source
   * of attacks
   */
  protected abstract boolean agentIsSource();

  private  IncrementalSubscription managerSubscription;

  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
    _log = (LoggingService) getServiceBroker().
      getService(this, LoggingService.class, null);
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }


  public void setCommunityService(CommunityService cs) {
    //System.out.println(" set community services Servlet component :");
    this._cs=cs;
  }
  public CommunityService getCommunityService() {
    return this._cs;
  }

  public void setParameter(Object o){
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() > 1) {
      _log.warn("Unexpected number of parameters given. Expecting 1, got " +
                l.size());
    }
    if (l.size() > 0) {
      _managerRole = l.get(0).toString();
      if (_log != null && _log.isInfoEnabled()) {
        _log.info("Setting M&R Manager role to " + _managerRole);
      }
    }
  }

  /**
   * Register this sensor's capabilities
   */
  protected void setupSubscriptions() {
    myAddress = getAgentIdentifier();
    _blackboard = getBlackboardService();
    
    ServiceBroker sb = getBindingSite().getServiceBroker();
    _scs = (SecurityContextService)
      sb.getService(this, SecurityContextService.class, null);
    _cmrFactory = (CmrFactory) getDomainService().getFactory("cmr");
    _idmefFactory = _cmrFactory.getIdmefMessageFactory();
    if(_log == null) {
      _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    }
    _csu = new CommunityServiceUtil(sb);
    // register this sensor's capabilities
    if( !_blackboard.didRehydrate()) {
      getSecurityManager();
    }
    managerSubscription=(IncrementalSubscription)getBlackboardService().subscribe(new ManagerAgentPredicate());
    

    /*
    Thread td=Thread.currentThread();
    _log.error("Current thread is :"+td.toString());
    ThreadService ts = (ThreadService)sb.getService(this,
                                                    ThreadService.class, null);
    ts.getThread(this, new Runnable() {
        public void run() {
          getSecurityManager();
        }
      }).start();
    sb.releaseService(this, ThreadService.class, ts);
    */
  }
  
   
 

  /**
   * doesn't do anything
   */
  protected void execute(){
    if(!managerSubscription.hasChanged()){
      return;
    }
     Collection  mgrAgentCol=managerSubscription.getAddedCollection();
     if(!mgrAgentCol.isEmpty()) {
       Iterator iter=mgrAgentCol.iterator();
       MnRManagerObject mgrObject=null;
       while(iter.hasNext()){
         mgrObject=(MnRManagerObject)iter.next();
         if(myAddress.equals(mgrObject.getMgrAddress())){
           myManagerAddress=mgrObject.getMgrAddress();
           if(_log.isDebugEnabled()){
             _log.debug("Setting Mgr Address from execute of Sensor plugin:");
           }
            _log.info("Setting Mgr Address from execute of Sensor plugin:"+ "myAddress "+ myAddress +" mgrAddress " +myManagerAddress );
         }
         registerCapabilities(myManagerAddress); 
       }
     }
  }

  private void getSecurityManager() {
    if(_log.isDebugEnabled()) {
      _log.debug("getSecurityManager called in Sensor Plugin:"); 
    }
    CommunityServiceUtilListener listener = new CommunityServiceUtilListener() {
	public void getResponse(Set entities) {
          if(_log.isDebugEnabled()) {
            _log.debug(" Call Back called for agent :"+  myAddress);
          }
	  Iterator it = entities.iterator();
	  if (entities.size() == 0) {
	    _log.warn("Could not find a security manager");
	  }
	  else if (entities.size() > 1) {
	    _log.warn("Found more than one security manager");
	  }
	  else {
	    Entity entity = (Entity) it.next();
	    MessageAddress addr = MessageAddress.
	      getMessageAddress(entity.getName());
	    // Now register capabilities
            if(myManagerAddress==null) {
              myManagerAddress=addr;
              if(_log.isDebugEnabled()){
                _log.error("CommunityServiceUtilListener thread is :" + Thread.currentThread().hashCode());
                _log.debug("Setting Manager for Sensor Plugin -- Manager  : "+ myManagerAddress +" For Agent : " +myAddress);
              }
              _log.info("Setting Manager for Sensor Plugin -- Manager 2: "+ myManagerAddress +" For Agent : " +myAddress);
              registerCapabilities(addr);
            }
	  }
	}
      };
    if(_log.isDebugEnabled()) {
      _log.debug("findSecurityManager from Communityservice util called in Sensor Plugins getSecurityManager:"
                 +myAddress.toString()); 
    }
    _csu.findMySecurityManager(CommunityServiceUtil.MONITORING_SECURITY_COMMUNITY_TYPE,listener);
  }

  /**
   * register the capabilities of the sensor
   */
  private void registerCapabilities(final MessageAddress myManager){
    final List capabilities = new ArrayList();
    final List targets = new ArrayList();
    final List  sources=new ArrayList();
    final List  data =new ArrayList() ;
    if (_log.isDebugEnabled()) {
      _log.debug("Current thread is :" + Thread.currentThread());
    }
    if(myManager == null) {
      // manager may not have been initialize yet
      return;
    }
    // if agent is the target then add the necessary information to the registration
    if(agentIsTarget()) {
      List tRefList = new ArrayList(1);
      //data = new ArrayList(1);
      Address tAddr = _idmefFactory.createAddress(myAddress.toString(),
                                                  null, Address.URL_ADDR);
      Target t = _idmefFactory.createTarget(null, null, null, null, null, null);
      // add the target ident to the reference ident list
      tRefList.add(t.getIdent());
      targets.add(t);
      // since there isn't a data model for cougaar Agents, the Agent object is
      // added to the AdditionalData of an IDMEF message
      Agent tAgent = _idmefFactory.createAgent(myAddress.toString(),
                                               null, null, tAddr, tRefList);
      data.add(_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
    }
    if(agentIsSource()) {
      List sRefList = new ArrayList(1);
      /*
      if(data==null) {
        data = new ArrayList(1);
      }
      */
      Address sAddr = _idmefFactory.createAddress(myAddress.toString(),
                                                  null, Address.URL_ADDR);
      Source s = _idmefFactory.createSource(null, null, null, null, null);
      // add the target ident to the reference ident list
      sRefList.add(s.getIdent());
      sources.add(s);
      // since there isn't a data model for cougaar Agents, the Agent object is
      // added to the AdditionalData of an IDMEF message
      Agent sAgent = _idmefFactory.createAgent(myAddress.toString(),
                                               null, null, sAddr, sRefList);
      data.add(_idmefFactory.createAdditionalData(Agent.SOURCE_MEANING, sAgent));
    }

    String []classifications = getClassifications();
    for(int i = 0; i < classifications.length; i++) {
      Classification classification =
        _idmefFactory.createClassification(classifications[i], null);
      capabilities.add(classification);
    }


    Runnable task =new Runnable() {
      public void run() {
        RegistrationAlert reg =
          _idmefFactory.createRegistrationAlert( getSensorInfo(),
                                                 null,
                                                 targets,
                                                 capabilities,
                                                 data,
                                                 IdmefMessageFactory.newregistration,
                                                 IdmefMessageFactory.SensorType,
                                                 myAddress.toString());
         NewEvent regEvent = _cmrFactory.newEvent(reg);
        _blackboard.openTransaction();
        if(myAddress.equals(myManager)) {
          _log.info("Publishing registration to local blackboard:");
          _blackboard.publishAdd(regEvent);
        }
        else{
          CmrRelay regRelay = _cmrFactory.newCmrRelay(regEvent, myManager);
          _blackboard.publishAdd(regRelay);
          _log.info("Publishing registration as relay:");
        }
        _blackboard.closeTransaction();
        _log.debug("Registered sensor successfully!");
      }
    };

    ServiceBroker sb =getBindingSite().getServiceBroker();
    ThreadService ts = (ThreadService)
      sb.getService(this, ThreadService.class, null);
    ts.getThread(this, task).schedule(0);
    sb.releaseService(this, ThreadService.class, ts);
    if(sb!=null) {
      sb.releaseService(this,CommunityService.class,_cs);
      _cs=null;
    }
    return;
  }

  private class Semaphore {
    private int _available;
    public Semaphore(int max_available) {
      _available = max_available;
    }
    public synchronized int add() {
      return _available++;
    }
    public synchronized int remove() {
      return _available--;
    }
  }

  private void printCommunityInfo(CommunityService cs, Collection communities) {
    Iterator c = communities.iterator();

    while(c.hasNext()) {
      final String communityName = (String)c.next();
      CommunityResponseListener crl = new CommunityResponseListener() {
	  public void getResponse(CommunityResponse resp) {
	    Object response = resp.getContent();
	    if (!(response instanceof Set)) {
	      String errorString = "Unexpected community response class:"
		+ response.getClass().getName() + " - Should be a Set";
              _log.error(errorString);
	      throw new RuntimeException(errorString);
	    }
            printCommunities((Set) response, communityName);
	  }
	};
      Collection results =
        cs.searchCommunity(communityName,
                           "(Role=" + _managerRole + ")",
                           false, // not a recursive search
                           Community.AGENTS_ONLY,
                           crl);
      if (results != null) {
        printCommunities(results, communityName);
      }
    }
  }

  private void printCommunities(Collection communities, String communityName) {
    StringBuffer sb = new StringBuffer();
    Iterator it = communities.iterator();
    while (it.hasNext()) {
      Entity entity = (Entity) it.next();
      sb.append("Manager for ").append(communityName).
        append(":").append(entity.getName()).append("\n");
    }
    // We have all the answers
    _log.debug(sb.toString());
  }

  /**
   * method used to determine if the plugin is located in the same
   * agent as the enclave security manager
   * @deprecated
   */
  private boolean isSecurityManagerLocal(CommunityService cs,
					 String community,
					 String agentName) {

    Collection agents = null;
    // TODO: This method is not used anymore, but it would have to
    // be fixed if used again.
    //Collection agents = cs.searchByRole(community, _managerRole);
    Iterator i = agents.iterator();

    while(i.hasNext()) {
      MessageAddress addr = (MessageAddress)i.next();
      if(addr.toString().equals(agentName)) {
        return true;
      }
    }
    return false;
  }

  private static class RegistrationPredicate implements UnaryPredicate {
    private String _agent;
    private List _targets;
    private List _capabilities;
    private List _data;
    private String _agentName;
    private SensorInfo _sensor;

    public RegistrationPredicate(SensorInfo sensor,
                                 List targets,
                                 List capabilities,
                                 List data,
                                 String agentName) {
      _sensor = sensor;
      _targets = targets;
      _capabilities = capabilities;
      _data = data;
      _agent = agentName;
    }

    public static boolean arrayEquals(Object arr[], List list) {
      if ((arr == null || arr.length == 0) &&
          (list == null || list.size() == 0)) {
        return true;
      }
      if (arr == null || list == null || arr.length != list.size()) {
        return false;
      }

      Iterator iter = list.iterator();
      for (int i = 0; i < arr.length; i++) {
        Object o = iter.next();
        if (!(arr[i] == null && o == null)) {
          if (arr[i] == null || o == null) {
            return false;
          }
          if (!arr[i].equals(o)) {
            return false;
          }
        }
      }
      return true;
    }

    public boolean execute(Object o) {
      if (!(o instanceof CmrRelay)) {
        return false;
      } // end of if (!(o instanceof CmrRelay))
      CmrRelay cmr = (CmrRelay) o;
      Object content = cmr.getContent();
      if (!(content instanceof NewEvent)) {
        return false; // not a registration event
      } // end of if (!(content instanceof Event))
      NewEvent ev = (NewEvent) content;
      IDMEF_Message msg = ev.getEvent();
      if (!(msg instanceof RegistrationAlert)) {
        return false;
      } // end of if (!(msg instanceof RegistrationAlert))
      RegistrationAlert r = (RegistrationAlert) msg;
      if (!_agent.equals(r.getAgentName()) ||
          r.getOperation_type() != IdmefMessageFactory.newregistration ||
          !IdmefMessageFactory.SensorType.equals(r.getType())) {
        return false;
      }

      return (arrayEquals(r.getClassifications(),_capabilities) &&
              arrayEquals(r.getAdditionalData(),_data) &&
              arrayEquals(r.getTargets(),_targets) &&
              ((r.getAnalyzer() == null && _sensor.getModel() == null) ||
               (r.getAnalyzer() != null &&
                r.getAnalyzer().equals(_sensor.getModel()))));
    }
  }
  private CommunityServiceUtil _csu;

  protected CommunityService _cs;
  protected BlackboardService _blackboard;
  protected DomainService _domainService;
  protected SecurityContextService _scs;
  protected LoggingService _log;
  protected CmrFactory _cmrFactory;
  protected IdmefMessageFactory _idmefFactory;
  protected String _managerRole = "Manager"; // default value
  protected static Hashtable _eventCache = new Hashtable();
  protected EventPublisher _publisher;

  protected void setPublisher(EventPublisher publisher) {
    _publisher = publisher;
  }
  
  protected void publishIDMEFEvent() {
    List events = null;
    synchronized (_eventCache) {
      Object o = _eventCache.get(getClass());
      if (o != null && o instanceof List) {
        events = (List)o;
      }
      _eventCache.put(getClass(), _publisher);
    }
    if (events != null) {
      if (_log.isDebugEnabled()) {
        _log.debug("publishIDMEFEvent: " + events.size() + " pending.");
      }
      ServiceBroker sb = getServiceBroker();
      ThreadService ts = (ThreadService)
        sb.getService(this, ThreadService.class, null);
      final List fEvents = events;
      ts.getThread(this, new Runnable() {
          public void run() {
            _publisher.publishEvents(fEvents);
          }
        }).start();
      sb.releaseService(this, ThreadService.class, ts);
    }
  }
  
  public static void publishEvent(Class cl, FailureEvent event) {
    EventPublisher publisher = null;
    List events = null;

    Object o = _eventCache.get(cl);

    if (o != null) {
      if (o instanceof EventPublisher) {
        publisher = (EventPublisher)o;
      }
      else if (o instanceof List) {
        events = (List)o;
      }
    }

    if (publisher != null) {
      publisher.publishEvent(event);
    }
    else {
      if (events == null) {
        events = new ArrayList();
      }
      events.add(event);
      _eventCache.put(cl, events);
    }
  }

  public static int getCacheSize() {
    return _eventCache.size();
  }
}
