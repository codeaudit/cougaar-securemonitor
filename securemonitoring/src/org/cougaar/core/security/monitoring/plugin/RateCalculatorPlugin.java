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

import org.cougaar.core.adaptivity.Condition;
import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;
import org.cougaar.util.UnaryPredicate;

import java.io.Serializable;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;

/**
 * Queries for IDMEF messages and creates a 
 * condition from the results. The arguments to the plugin
 * component in the .ini file determine how rates are
 * generated.
 *
 * <table width="100%">
 * <tr><td>Parameter Number</td><td>Type</td><td>Meaning</td></tr>
 * <tr><td>1</td><td>Integer</td><td>Poll interval in seconds.
 *   Determines how often the rate is recalculated.</td></tr>
 * <tr><td>2</td><td>Integer</td><td>Window for IDMEF messages to be gathered
 * over to determine the rate. The value is a duration in 
 * seconds.</td></tr>
 * <tr><td>3</td><td>String</td><td>The IDMEF message category to examine.</td></tr>
 * <tr><td>4</td><td>String</td><td>The name of the condition to post to the blackboard</td></tr>
 * </table>
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.servlet.SimpleServletComponent(org.cougaar.planning.servlet.PlanViewServlet, /tasks)
 * plugin = org.cougaar.core.security.monitorin.plugin.RateCalculatorPlugin(20,60,org.cougaar.core.security.monitoring.LOGIN_FAILURE,org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 *
 * Note that on rehydration, the rate calculated from events before
 * the blackboard was saved is discarded and the window is cleared.
 *
 * @author George Mount <gmount@nai.com>
 */
public class RateCalculatorPlugin extends ComponentPlugin {

  final static long SECONDSPERDAY = 60 * 60 * 24;

  /** 
   * The number of seconds that the poll can be delayed before there
   * is a problem. 
   */
  private static final int OVERSIZE = 600;

  /** Logging service */
  private LoggingService _log;

  /** The number of seconds between rate updates */
  protected int    _pollInterval    = 0;

  /** 
   * The amount of time to take into account when determining the
   * rate.
   */
  protected int    _window          = 0;

  /**
   * Buckets, one second each, containing the count of appropriate
   * IDMEF messages that happened within that second.
   */
  protected int    _messages[]      = null;

  /**
   * The total number of IDMEF messages that happened within the window
   */
  protected int    _totalMessages   = 0;

  /**
   * The time that the service was started
   */
  protected long   _startTime       = System.currentTimeMillis();

  /**
   * Subscription to the IDMEF messages on the local blackboard
   */
  protected IncrementalSubscription _subscription;

  /**
   * The IDMEF classification to search for.
   */
  protected String _classification;

  /**
   * The condition name for this rate
   */
  protected String _conditionName;

  /**
   * Keep for publishing to the blackboard for persistence purposes
   */
  private RateCalculatorInfo _persistRate;

  /**
   * Has the condition been published already?
   */
  private boolean _conditionPublished;

  /**
   * The predicate for the rate information from a restored session.
   */
  private final UnaryPredicate RATEINFO_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof RateCalculatorInfo &&
                ((RateCalculatorInfo) o).conditionName.equals(_conditionName));
      }
    };

  /**
   * The predicate indicating that we should retrieve all new
   * IDMEF messages with a given classification
   */
  private final UnaryPredicate SUBSCRIPTION_PREDICATE = 
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
                if (_classification.equals(cs[i].getName())) {
                  return true;
                }
              }
            }
          }
        }
        return false;
      }
    };
    
  /**
   * Predicate to indicate if we need to recreate the rate condition
   * or use the one rehydrated from the serialized blackboard
   */
  private final UnaryPredicate RATE_CONDITION_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        return (o instanceof RateCondition &&
                ((RateCondition)o).getName().equals(_conditionName));
      }
    };

  /**
   * Gets the poll interval (seconds between rate updates),
   * window (the number of seconds over which the rate
   * is determined), IDMEF classification, and condition name.
   */
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;

    String paramName = "poll interval";
    Iterator iter = l.iterator();
    String param = "";
    try {
      param = iter.next().toString();
      _pollInterval = Integer.parseInt(param);

      paramName = "window duration";
      param = iter.next().toString();
      _window = Integer.parseInt(param);

      paramName = "IDMEF message classification";
      _classification = iter.next().toString();
      
      paramName = "Rate condition name";
      _conditionName = iter.next().toString();
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
    if (_window <= 0 || _pollInterval <= 0) {
      throw new IllegalArgumentException("You must provide positive " +
                                         "window and poll interval arguments");
    }

    _messages = new int[_window + OVERSIZE];
    for (int i = 0; i < _messages.length; i++) {
      _messages[i] = 0;
    }
  }

  /**
   * Sets up the rate task for
   * updating the rate at the interval specified in the configuartion
   * parameters. 
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    if (_log.isDebugEnabled()) {
      _log.debug("Poll interval: " + _pollInterval
		 + " Rate condition: " + _conditionName
		 + " IDMEF classification: " + _classification) ;
    }
    BlackboardService bbs = getBlackboardService();
    _subscription = (IncrementalSubscription)
      bbs.subscribe(SUBSCRIPTION_PREDICATE);

    ThreadService ts = (ThreadService) getServiceBroker().
      getService(this, ThreadService.class, null);

    rehydrate();

    // remove the old rate condition(s) -- should be only one at most
    Collection c = bbs.query(RATE_CONDITION_PREDICATE);
    RateCondition rc = null;
    if (!c.isEmpty()) {
      Iterator iter = c.iterator();
      rc = (RateCondition) iter.next();
      while (iter.hasNext()) {
        bbs.publishRemove(iter.next());
      } // end of while (iter.hasMore())
    }
    ts.getThread(this, new RateTask(rc)).schedule(
      0, ((long)_pollInterval) * 1000);
  }

  /**
   * Counts the number of IDMEF messages and updates the count for
   * the current second.
   */
  public void execute() {
    if (_subscription.hasChanged()) {
      long now = System.currentTimeMillis();

      Collection added = _subscription.getAddedCollection();
      int count = added.size();
      if (_log.isDebugEnabled()) {
	_log.debug("Received " + count + " events for " + _classification);
      }
      synchronized (_messages) {
        _messages[(int)((now - _startTime)/1000)%_messages.length] += count;
        _totalMessages += count;
      }
    }
  }

  /**
   * A condition published to the blackboard whenever there is a 
   * rate change. The target for this condition is the
   * Adaptivity Engine.
   */
  static class RateCondition
    implements Condition, Serializable, UniqueObject {
    Double _rate;
    UID _uid;
    static final OMCRangeList RANGE = 
      new OMCRangeList(new Double(0.0), new Double(Integer.MAX_VALUE));
    String _name;
 
    public RateCondition(String name) {
      _name = name;
      setRate(-1);
    }
      
    public OMCRangeList getAllowedValues() {
      return RANGE;
    }
     
    public String getName() {
      return _name;
    }
  
    public Comparable getValue() {
      return _rate;
    }

    public void setRate(double rate) {
      _rate = new Double(rate);
    }

    public String toString() {
      return _name + " = " + _rate;
    }

    public UID getUID() {
      return _uid;
    }
    
    public void setUID(UID uid) {
      _uid = uid;
    }
  }

  /**
   * This class is used internally to periodically update the 
   * rate. It relies on the ThreadService to trigger
   * its run() method.
   */
  class RateTask implements Runnable {
    int  _lastCleared= (OVERSIZE + (int) 
                        (_startTime - 
                         System.currentTimeMillis())/1000)%_messages.length;
    int  _prevTotal = -1;

    /**
     * The rate that was last reported.
     */
    protected RateCondition _rate = null;

    public RateTask(RateCondition rate) {
      if (rate != null) {
        _rate = rate;
        _rate.setRate(-1);
      }
    }

    /**
     * Counts the IDMEF messages and checks to see if the rate needs
     * to be reported to the Adaptivity Engine. It also cleans out the
     * buckets expected to be filled before the next call to run() is
     * triggered.
     */
    public void run() {
      boolean report = false;
      synchronized (_messages) {
        long now = System.currentTimeMillis();
        _persistRate.lastUpdate = now;
        BlackboardService bbs = getBlackboardService();
        bbs.openTransaction();
        bbs.publishChange(_persistRate);
        bbs.closeTransaction();
        int  bucketOn = (int)((now - _startTime)/1000)%_messages.length;

        if (_totalMessages != _prevTotal) {
          _prevTotal = _totalMessages;
          report = true;
        }

        // clear the buckets between 
        int nextCleared = (bucketOn + _pollInterval + OVERSIZE) % 
          _messages.length;
        while (_lastCleared != nextCleared) {
          _totalMessages -= _messages[_lastCleared];
          _messages[_lastCleared] = 0;
          _lastCleared = (_lastCleared + 1) % _messages.length;
        }
      }
      if (_log.isDebugEnabled()) {
	_log.debug(_conditionName + " - Total messages: " + _totalMessages);
      }
      if (report || !_conditionPublished) {
        reportRate(_prevTotal);
      }
    }

    /**
     * Publishes a change in the rate condition to the
     * blackboard.
     */
    private void reportRate(int messageCount) {
      double rate = (messageCount * SECONDSPERDAY / _window);
      if (_log.isDebugEnabled()) {
        _log.debug(_conditionName + " = " + rate +
                   " " + _classification + "/day");
      } // end of if (_log.isDebugEnabled())

      boolean add = false;
      if (_rate == null) {
        _rate = new RateCondition(_conditionName);
        UIDService uids = 
          (UIDService) getServiceBroker().getService(this,
                                                     UIDService.class,
                                                     null);
        uids.registerUniqueObject(_rate);
        add = true;
      }
      _rate.setRate(rate);
      getBlackboardService().openTransaction();
      if (add) {
        getBlackboardService().publishAdd(_rate);
      } else {
        getBlackboardService().publishChange(_rate);
      }
      _conditionPublished = true;
      getBlackboardService().closeTransaction();
    }
  }

  /**
   * Rehydrates the rate from the blackboard taking into account the
   * new time.
   */
  private void rehydrate() {
    Collection rateInfo = getBlackboardService().query(RATEINFO_PREDICATE);
    RateCalculatorInfo ri;
    if (rateInfo.isEmpty()) {
      if (_log.isInfoEnabled()) {
        _log.info("No rehydration for " + _conditionName);
      } // end of if (_log.isInfoEnabled())
      
      _conditionPublished = false;

      UIDService uids = 
        (UIDService) getServiceBroker().getService(this,
                                                   UIDService.class,
                                                   null);
      UID uid;
      if (uids != null) {
        uid = uids.nextUID();
      } else {
        uid = new UID("RateCalculatorPlugin", (new SecureRandom()).nextLong());
      } // end of else
      
      ri = new RateCalculatorInfo(_messages,_startTime,
                                  _startTime,_conditionName, uid);
      getBlackboardService().publishAdd(ri);
    } else {
      _conditionPublished = true ;
      ri = (RateCalculatorInfo) rateInfo.iterator().next();
      if (_log.isInfoEnabled()) {
        _log.info("Rehydrating " + _conditionName);
      } // end of if (_log.isInfoEnabled())
      if (_startTime - ri.lastUpdate < _window) {
        // we must use some of the old data for the new rate:
        int lastBucket = (int) (((ri.lastUpdate - ri.startTime)/1000) % 
                                ri.messages.length);
        long firstTime = _startTime - _window * 1000;
        int firstBucket = (int) (((firstTime - ri.startTime)/1000) % 
                                 ri.messages.length);
        int count = lastBucket - firstBucket;
        if (count < 0) {
          count += ri.messages.length;
        } // end of if (count < 0)
        
        for (int i = firstBucket; i <= lastBucket; 
             i = (i + 1) % ri.messages.length) {
          int ct = ri.messages[i];
          _messages[_messages.length - count] = ct;
          _totalMessages += ct;
          count--;
        }
      }
      ri.messages = _messages;
      ri.startTime = _startTime;
      ri.lastUpdate  = _startTime;
      getBlackboardService().publishChange(ri);
    }
    _persistRate = ri;
  }
}
