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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.cougaar.core.adaptivity.OMCRange;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.component.ServiceAvailableEvent;
import org.cougaar.core.component.ServiceAvailableListener;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.constants.AdaptiveMnROperatingModes;
import org.cougaar.core.security.constants.IdmefAssessments;
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.event.EventClassification;
import org.cougaar.core.security.monitoring.event.LoginFailureEvent;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.security.services.acl.UserService;
import org.cougaar.core.security.services.acl.UserServiceException;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.Community;
import org.cougaar.core.service.community.CommunityChangeEvent;
import org.cougaar.core.service.community.CommunityChangeListener;
import org.cougaar.core.service.community.CommunityResponse;
import org.cougaar.core.service.community.CommunityResponseListener;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.multicast.AttributeBasedAddress;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;

/**
 * This class queries login failures and will lockout users who
 * have failed to login too many times. The values for maximum
 * login failures and lockout duration are retrieved from
 * Operating Modes driven by the adaptivity engine.
 * Add these lines to your agent:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400,org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. The third argument is the name
 * of the operating mode that the plugin uses to determine when a threshold has
 * been exceed that warrants an action.
 */
public class UserLockoutPlugin extends ResponderPlugin {

  private long _lockoutTime   = 1000 * 60 * 60 * 24; // 1 day

  private UserService _userService;
  private IncrementalSubscription _lockoutDurationSubscription;

  private OperatingMode _lockoutDurationOM = null;
  private static final SensorInfo _sensor = new ULSensor();

  // fixed
  private final String         _managerRole   = "Manager";

  private final static Action[] USER_LOCKOUT_ACTION = new Action[] {
    new Action(Action.OTHER, IdmefAssessments.USER_LOCKOUT)
  };
  private final static Confidence USER_LOCKOUT_CONFIDENCE =
  new Confidence(Confidence.MEDIUM, null);

  private final static Assessment USER_LOCKOUT_ASSESSMENT =
  new Assessment(new Impact(Impact.MEDIUM, Impact.SUCCEEDED,
                            Impact.USER, IdmefAssessments.USER_LOCKOUT),
                 USER_LOCKOUT_ACTION,
                 USER_LOCKOUT_CONFIDENCE);

  public static final Classification LOGIN_FAILURE =
  new Classification(IdmefClassifications.LOGIN_FAILURE, "",
                     Classification.VENDOR_SPECIFIC);
   
  private static final String[] CLASSIFICATIONS = {
    IdmefClassifications.LOGIN_FAILURE
  };
  
  private boolean addedListener =false;
  /**
   * The predicate indicating that we should retrieve all new
   * login failures
   */
  private static final UnaryPredicate LOGIN_FAILURES_PREDICATE =
  new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof Event) {
        IDMEF_Message msg = ((Event) o).getEvent();
        if (msg instanceof RegistrationAlert ||
            msg instanceof ConsolidatedCapabilities) {
          return false;
        }
        if (msg instanceof Alert) {
          Alert alert = (Alert) msg;
          if (alert.getAssessment() != null) {
            return false; // never look at assessment alerts
          } // end of if (alert.getAssessment() != null)
          Classification cs[] = alert.getClassifications();
          if (cs != null) {
            for (int i = 0; i < cs.length; i++) {
              if (IdmefClassifications.LOGIN_FAILURE.equals(cs[i].getName())) {
                AdditionalData ad[] = alert.getAdditionalData();
                if (ad != null) {
                  for (int j = 0; j < ad.length; j++) {
                    if (LoginFailureEvent.FAILURE_REASON.equals(ad[j].getMeaning())) {
                      return (LoginFailureEvent.FAILURE_REASONS[KeyRingJNDIRealm.LF_PASSWORD_MISMATCH].equals(ad[j].getAdditionalData()));
                    }
                  }
                }
                return false;
              }
            }
          }
        }
      }
      return false;
    }
  };

  /**
   * For OperatingModes value range
   */
  private static final OMCRange []LD_VALUES = {
    new OMCThruRange(-1.0, Double.MAX_VALUE)
  };

  /**
   * Lockout duration operating mode range
   */
  private static final OMCRangeList LOCKOUT_DURATION_RANGE =
  new OMCRangeList(LD_VALUES);

  private static final String LOCKOUT_DURATION = AdaptiveMnROperatingModes.LOCKOUT_DURATION;

  /**
   * For the lockout duration OperatingMode
   */
  private static final UnaryPredicate LOCKOUT_DURATION_PREDICATE =
  new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof OperatingMode) {
        OperatingMode om = (OperatingMode) o;
        String omName = om.getName();
        if (LOCKOUT_DURATION.equals(omName)) {
          return true;
        }
      }
      return false;
    }
  };

  private static class RegistrationPredicate implements UnaryPredicate {
    private String _agent;

    public RegistrationPredicate(String agentName) {
      _agent = agentName;
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
      Classification cf[] = r.getClassifications();
      for (int i = 0; i < cf.length; i++) {
        if (cf[i] != null &&
            IdmefClassifications.LOGIN_FAILURE.equals(cf[i].getName())) {
          return true;
        }
      } // end of for (int i = 0; i < cf.length; i++)

      return false; // not the right classification
    }
  }

  public void execute() {
    if (_lockoutDurationSubscription.hasChanged()) {
      updateLockoutDuration();
    }
    super.execute();
  }

  public void start() {
    setUserService();
    super.start();
  }

  private void setUserService() {
    _userService = (UserService)
      getServiceBroker().getService(this, UserService.class, null);
    if(_userService==null) {
      Iterator iter = getServiceBroker().getCurrentServiceClasses();
      if(_log!=null){
        _log.error("Current services that can be obtained at UserLockout plugin are:"); 
      }
      Object object=null;
      while(iter.hasNext()){
        object =iter.next();
        if(_log!=null){
          _log.error("Service ----->"+ object.toString());
        }
      }
      if(_log!=null){
        _log.warn(" USER SERVICE is NULL adding Service listener");
      }
      if(!addedListener) {
        ServiceAvailableListener listener = new ServicesListener();
        getServiceBroker().addServiceListener(listener);
        addedListener=true;
      }
    }
  }

  protected void setupSubscriptions() {
    super.setupSubscriptions();

    BlackboardService blackboard = getBlackboardService();

    _lockoutDurationSubscription = (IncrementalSubscription)
      blackboard.subscribe(LOCKOUT_DURATION_PREDICATE);

    Collection c = blackboard.query(LOCKOUT_DURATION_PREDICATE);
    if (c.isEmpty()) {
      _lockoutDurationOM = new OperatingModeImpl(LOCKOUT_DURATION,
                                                 LOCKOUT_DURATION_RANGE,
                                                 new Double(_lockoutTime/1000));
      blackboard.publishAdd(_lockoutDurationOM);
    } else {
      _lockoutDurationOM = (OperatingMode) c.iterator().next();
      _lockoutTime = ((Number) _lockoutDurationOM.getValue()).longValue() * 1000;
    } // end of else

    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    ThreadService        ts           = (ThreadService)
      sb.getService(this, ThreadService.class, null);
    
    // get a thread to set up the community stuff for registration
    ts.getThread(this, new Runnable() {
        public void run() {
          setupCommunity();
          addCommunityListener(); 
        }
      }
      ).start();
    sb.releaseService(this, ThreadService.class, ts);
  }

 
  protected  String []getClassifications() {
    return CLASSIFICATIONS;

  }
  
  protected SensorInfo getSensorInfo() {
    return _sensor;
  } 
  private void addCommunityListener() {
    ServiceBroker sb = getServiceBroker();
    CommunityService cs = (CommunityService)
      sb.getService(this, CommunityService.class,null);
    cs.addListener(new CommunityChangeListener() {
        public String getCommunityName() {
          return null;
        }

        public void communityChanged(CommunityChangeEvent event) {
          //setupCommunity();

          Community community = event.getCommunity();
          try {
            if (event.getType() == CommunityChangeEvent.ADD_COMMUNITY) {
              if (_log.isDebugEnabled()) {
                _log.debug("Community changed: " + event);
              }
            }
            // else we don't care
            else {
              return;
            }

            Attributes attrs = community.getAttributes();
            Attribute attr = attrs.get("CommunityType");
            if (attr != null) {
              for (int i = 0; i < attr.size(); i++) {
                Object type = attr.get(i);
                if (type.equals(CommunityServiceUtil.SECURITY_COMMUNITY_TYPE)) {
                  // so community being changed is a security community
                  // we only care about changed to a new one
                  Set comSet = new HashSet();
                  comSet.add(community);
                  configureCommunity(comSet);
                }
              }
            }
          } catch (NamingException e) {
            throw new RuntimeException("This should never happen");
          }

        }
      });
    sb.releaseService(this, CommunityService.class, cs);
  }
  
  /**
   * method that takes an action against the culprit
   */
  protected void action(String culprit) throws Exception {
    if (_log.isDebugEnabled()) {
      _log.debug("locking out user (" + culprit + ")");
    } // end of if (_log.isDebugEnabled())
    if (_userService == null) {
      _log.info("User service was not set. Trying to get it");
      setUserService();
    }
    else {
      setUserService();
    }
    if (_userService == null) {
      String msg = "LDAP User service is not available. Cannot take action against " + culprit;
      _log.error(msg);
      throw new RuntimeException(msg);
    }
    else {
      final String localculprit=culprit;
      final long lockoutTime=_lockoutTime;
      ThreadService currentthreadService = (ThreadService)  getServiceBroker().getService(this, ThreadService.class, null); 
      if (_lockoutTime < 0) {
        Schedulable disablethread=currentthreadService.getThread(this, new Runnable( ){ 
            public void run(){
              try{
                _userService.disableUser(localculprit);
              }
              catch(UserServiceException use) {
                _log.warn("cannot disable user ",use);
              }
            }
          },"UserLockoutThread");
        disablethread.start();
      }
      else {
        Schedulable disablethread=currentthreadService.getThread(this, new Runnable( ){ 
            public void run(){ 
              try{
                _userService.disableUser(localculprit,lockoutTime);
              }
              catch(UserServiceException use) {
                _log.warn("cannot idable user ",use);
              } 
            }
          },"UserLockoutThread-withLockTime");
         disablethread.start();
      }                                                                                                                                         
    }
  }

  protected UnaryPredicate getFailurePredicate(){
    return LOGIN_FAILURES_PREDICATE;
  }

  /**
   * method that creates and publishes an IDMEF message with
   * an assessment specifying the action taken in response to
   * login failures exceeding a certain threshold.
   */
  protected void publishAssessment(String culprit) {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGIN_FAILURE);

    UserId uid = _idmefFactory.createUserId( culprit );
    List uids = new ArrayList();
    uids.add(uid);
    User u = _idmefFactory.createUser(uids);
    Target t = _idmefFactory.createTarget(null, u, null, null, null, null);
    List targets = new ArrayList();
    targets.add(t);

    Alert alert = _idmefFactory.createAlert(_sensor, new DetectTime(),
                                            null, targets, cfs, null);
    alert.setAssessment(USER_LOCKOUT_ASSESSMENT);
    NewEvent event = _cmrFactory.newEvent(alert);

    getBlackboardService().publishAdd(event);
  }

  /**
   * method to process a login failure
   */
  protected void processFailure() {
    _log.debug("Processing failure in UserLockout Plugin ");
    Enumeration iter = _failureQuery.getAddedList();
    while (iter.hasMoreElements()) {
      Event e = (Event) iter.nextElement();
      Alert alert = (Alert) e.getEvent();
      Target ts[] = alert.getTargets();
      for (int i = 0; i < ts.length; i++) {
        User user = ts[i].getUser();
        if (user != null) {
          UserId uids[] = user.getUserIds();
          if (uids != null) {
            for (int j = 0 ; j < uids.length; j++) {
              addCulprit(uids[j].getName());
            }
          }
        }
      }
    }
  }

  private List createClassifications() {
    ArrayList cfs = new ArrayList();
    cfs.add(LOGIN_FAILURE);
    return cfs;
  }

  private void setupCommunity() {
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    CommunityService     cs           = (CommunityService)
      sb.getService(this, CommunityService.class,null);
    if (cs == null) {
      _log.error("You must have CommunityPlugin in this agent for the UserLockoutPlugin to work");
    } // end of if (cs == null)

    CommunityResponseListener crl = new CommunityResponseListener() {
    	public void getResponse(CommunityResponse resp) {
    	  Object response = resp.getContent();
          if (response != null) {
            if (!(response instanceof Set)) {
              String errorString = "Unexpected community response class:"
                + response.getClass().getName() + " - Should be a Set";
              _log.error(errorString);
              throw new RuntimeException(errorString);
            }
            configureCommunity((Set)response);
          }
    	}
      };

    String filter = "(CommunityType=MnR-Security)";
    Collection communities =
      cs.searchCommunity(null, filter, false, Community.COMMUNITIES_ONLY, crl);
    if (communities != null) {
      configureCommunity((Set)communities);
    }

    sb.releaseService(this, CommunityService.class, cs);
  }

  private void configureCommunity(Set communities) {
    Iterator it = communities.iterator();
    MessageAddress messageAddress = null;
    while (it.hasNext()) {
      Community community = (Community) it.next();
      messageAddress = AttributeBasedAddress.
        getAttributeBasedAddress(community.getName(),
                                 "Role", _managerRole, null);
      break;
    }
    if (messageAddress == null) {
      _log.info("This agent does not belong to any community. Login failures won't be reported.");
      // may receive a add change message later
      return;
    }
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    ThreadService        ts           = (ThreadService)
      sb.getService(this, ThreadService.class, null);

    final MessageAddress addr = messageAddress;
    // no nested open transaction problems...
    ts.getThread(this, new Runnable() {
        public void run() {
          setupFailureSensor(addr);
        }
      }
      ).start();
    sb.releaseService(this, ThreadService.class, ts);
  }

  private void setupFailureSensor(MessageAddress managerAddress) {
    BlackboardService    bbs          = getBlackboardService();
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    AgentIdentificationService ais    = (AgentIdentificationService)
      sb.getService(this, AgentIdentificationService.class, null);
    String               agentName    = ais.getName();
    MessageAddress       myAddress    = ais.getMessageAddress();

    bbs.openTransaction();
    Collection c = bbs.query(new RegistrationPredicate(agentName));
    bbs.closeTransaction();
    if (!c.isEmpty()) {
      _log.info("Rehydrating - no need to publish sensor capabilities");
      return; // this is rehydrated and we've already registered
    } // end of if (!c.isEmpty())

    _log.info("No rehydration - publishing sensor capabilities");

    List capabilities = new ArrayList();
    capabilities.add(EventClassification.LOGINFAILURE);

    RegistrationAlert reg =
      _idmefFactory.createRegistrationAlert( _sensor, null, null,
                                             capabilities,
                                             null,
                                             IdmefMessageFactory.newregistration ,
                                             IdmefMessageFactory.SensorType,
                                             agentName);

    NewEvent regEvent = _cmrFactory.newEvent(reg);
    CmrRelay relay = _cmrFactory.newCmrRelay(regEvent, managerAddress);
    if (_log.isInfoEnabled()) {
      _log.info("Sending sensor capabilities to manager '" +
                managerAddress + "'");
    }
    bbs.openTransaction();
    bbs.publishAdd(relay);
    bbs.closeTransaction();
  }


  private void updateLockoutDuration() {
    _log.debug("Updating updateLockoutDuration");
    Collection oms = _lockoutDurationSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if (oms.size() > 0) {
      om = (OperatingMode)i.next();
      _log.debug("Lockout Duration updated to " + om.getValue() + " seconds.");
      _lockoutTime = (long)Double.parseDouble(om.getValue().toString()) * 1000;
    }
  }
  
  private class ServicesListener  implements ServiceAvailableListener {
    public void serviceAvailable(ServiceAvailableEvent ae) {
      Class sc = ae.getService();
      ServiceBroker sb = ae.getServiceBroker();
      if (sc == UserService.class ) {
        _log.info(" Got user service in user lockout plugin");
      }
      setUserService();
    }
  }
  private static class ULSensor implements SensorInfo {

    public String getName() {
      return "User Lockout Analyzer";
    }

    public String getManufacturer() {
      return "CSI";
    }

    public String getModel() {
      return "Servlet Login Failure";
    }

    public String getVersion() {
      return "1.0";
    }

    public String getAnalyzerClass() {
      return "org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin";
    }
  }
}
