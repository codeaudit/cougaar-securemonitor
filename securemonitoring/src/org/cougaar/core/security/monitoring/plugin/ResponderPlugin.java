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

// Cougaar core classes
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OMCThruRange;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.util.UnaryPredicate;

/**
 * This abstract class subscribes to failures and will take a response action
 * toward a culprit if the number of maximum failures are exceeded. The name
 * and value for maximum number of failures is obtained through a plugin parameter 
 * and is driven by the adaptivity engine.  The operating mode parameter is also
 * published to the blackboard.
 *
 * Concrete classes will need to extend from this class.  The arguments to the
 * plugin are:
 * 1. the duration to wait (in seconds) between checking
 * the failures for deletion.
 * 2. the amount of time to keep the failures before deleting it. 
 * 3. the max failure operating mode name
 *
 * For example:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.ConcreteResponder(600,86400,
 *  org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES)
 * </pre>
 * Here, the number 600 is the duration to wait (in seconds) between checking
 * the login failures for deletion. 86400 represents the amount of time to
 * keep the login failures before deleting it. 
 * org.cougaar.core.security.monitoring.MAX_LOGIN_FAILURES is the operating mode
 * that the ConcreteResponder requires to determine when to take action on a culprit.
 */
public abstract class ResponderPlugin extends SensorPlugin {
  
  protected int  _maxFailures   = 3;
  protected long _cleanInterval = 1000 * 60 * 10;      // 10 minutes
  protected long _rememberTime  = 1000 * 60 * 60;      // 1 hour

  protected LoggingService  _log;
  protected IncrementalSubscription _maxFailureSubscription;

  protected OperatingMode _maxFailureOM = null;
  protected String _maxFailureOMString = null;
  
  /**
   * Subscription to the message failures on the local blackboard
   */
  protected IncrementalSubscription _failureQuery;
  protected FailureCache _failureCache = new FailureCache();
  protected IdmefMessageFactory  _idmefFactory;
  protected CmrFactory _cmrFactory;
  
  private DomainService _domainService = null;
  
   /**
   * For the max failure OperatingMode
   */
  protected UnaryPredicate _maxFailurePredicate = null;
 
   
  /**
   * Max message failure operating mode range
   */
  private static final OMCRangeList MAX_FAILURE_RANGE =
      new OMCRangeList(new OMCThruRange(1.0, Double.MAX_VALUE ));
  
  /**
   * abstract method that takes an action against the culprit
   */
  protected abstract void action(String culprit) throws Exception;
  /**
   * abstract method that creates and publishes an IDMEF message with
   * an assessment specifying the action taken in response to failures
   * exceeding a certain threshold.
   */ 
  protected abstract void publishAssessment(String culprit); 
  /**
   * abstract method to process a specific failure
   */
  protected abstract void processFailure();
  /**
   * abstract method to obtain the predicate for a specific failure
   */
  protected abstract UnaryPredicate getFailurePredicate();
 
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    _domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return _domainService;
  }
    
  protected boolean agentIsTarget() {
    return false;
  }

  protected boolean agentIsSource() {
    return false;
  }
  
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;

    String paramName = "clean interval";
    Iterator iter = l.iterator();
    String param = "";
    try {
      param = iter.next().toString();
      _cleanInterval = Long.parseLong(param) * 1000;

      paramName = "failure memory";
      param = iter.next().toString();
      _rememberTime = Long.parseLong(param) * 1000;
      
      paramName = "max failure operating mode";
      _maxFailureOMString = iter.next().toString();
    } catch (NoSuchElementException e) {
      throw new IllegalArgumentException("You must provide a " +
                                        paramName +
                                        " argument");
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("Expecting integer for " +
                                         paramName +
                                         ". Got (" +
                                         param + ")");
    }
    if (_cleanInterval <= 0 || _rememberTime <= 0) {
      throw new IllegalArgumentException("You must provide positive " +
                                         "clean interval and failure memory " +
                                         "arguments");
    }
  }
  
  protected void setupSubscriptions() {
    super.setupSubscriptions();
    _maxFailurePredicate =  new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
          OperatingMode om = (OperatingMode) o;
          _log.debug("getting name of operating mode!");
          String omName = om.getName();
          if (_maxFailureOMString.equals(omName)) {
            return true;
          }
        }
        return false;
      }
    };
    
    _log = (LoggingService)
	    getServiceBroker().getService(this, LoggingService.class, null);
    
    BlackboardService blackboard = getBlackboardService();
    DomainService ds = getDomainService();
    _cmrFactory = (CmrFactory) ds.getFactory("cmr");
    _idmefFactory = _cmrFactory.getIdmefMessageFactory();
    _failureQuery = (IncrementalSubscription)
      blackboard.subscribe(getFailurePredicate());
   
    _maxFailureSubscription = (IncrementalSubscription)
      blackboard.subscribe(_maxFailurePredicate);
    
    // determine if we should publish this operating mode or not
    Collection c = blackboard.query(_maxFailurePredicate);
    if(c != null && c.size() > 0) {
      _maxFailureOM = (OperatingMode)c.iterator().next();
    }
    else {
      _maxFailureOM = new OperatingModeImpl(_maxFailureOMString, 
                                            MAX_FAILURE_RANGE, 
                                            new Double(_maxFailures));
      blackboard.publishAdd(_maxFailureOM);
    }
    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);
    ts.getThread(this, _failureCache).schedule(
      0, ((long)_cleanInterval) * 1000);
  }

  public void execute() {
    super.execute();
    if (_maxFailureSubscription.hasChanged()) {
      updateMaxFailures();
    }
    if (_failureQuery.hasChanged()) {
      processFailure();
    }
  }

  protected void addCulprit(String culprit) {
    _log.debug(" adding culprit :"+ culprit);
    synchronized (_failureCache) {
      _failureCache.add(culprit); 
    }
  }
  
  private void updateMaxFailures() {
    Collection oms = _maxFailureSubscription.getChangedCollection();
    Iterator i = oms.iterator();
    OperatingMode om = null;
    if (oms.size() > 0) {
      om = (OperatingMode)i.next();
      _log.debug("Max failures updated to " + om.getValue() + ".");
      _maxFailures = (int) Double.parseDouble(om.getValue().toString());
    }
  }

  private class FailureCache implements Runnable {
    HashMap _failures = new HashMap();
    
    public FailureCache() {
    }

    public void add(String culprit) {
      boolean takeAction = false;
      CacheNode failure = null;
      synchronized (_failureCache) {
        failure = (CacheNode) _failures.get(culprit);
        if (failure == null) {
          failure = new CacheNode();
          _failures.put(culprit, failure);
        }
        failure.failureCount++;
        if (failure.failureCount >= _maxFailures) {
          _failures.remove(culprit);
          takeAction = true;
        }
        failure.lastFailure = System.currentTimeMillis();
      }
      if (takeAction) {
        try {
          action(culprit);
          publishAssessment(culprit);
        } catch (Exception e) {
          _log.error("Error taking action against " + culprit + ": " + e.toString());
          synchronized (_failureCache) {
            _log.debug("putting culprit :"+culprit +"back to failure cache");
            _failures.put(culprit, failure); // put it back in...
          }
        }
      }
    }

    public void run() {
      long deleteTime = System.currentTimeMillis() - _rememberTime;
      synchronized (_failureCache) {
        Iterator iter = _failures.entrySet().iterator();
        while (iter.hasNext()) {
          Map.Entry entry = (Map.Entry) iter.next();
          CacheNode failure = (CacheNode) entry.getValue();
          if (failure.lastFailure < deleteTime) {
            iter.remove();
          }
        }
      }
    }
  }

  protected static class CacheNode {
    int  failureCount = 0;
    long lastFailure;
  }
}
