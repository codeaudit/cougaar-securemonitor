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
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.EventImpl;
import org.cougaar.core.security.monitoring.blackboard.FormatEvent;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUp;
import org.cougaar.core.security.monitoring.blackboard.MRAgentLookUpReply;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.service.AgentIdentificationService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.lib.aggagent.query.AggregationQuery;
import org.cougaar.lib.aggagent.query.AggregationResultSet;
import org.cougaar.lib.aggagent.query.QueryResultAdapter;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.query.ScriptSpec;
import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.lib.aggagent.util.Enum.Language;
import org.cougaar.lib.aggagent.util.Enum.QueryType;
import org.cougaar.lib.aggagent.util.Enum.ScriptType;
import org.cougaar.lib.aggagent.util.Enum.UpdateMethod;
import org.cougaar.lib.aggagent.util.Enum.XmlFormat;
import org.cougaar.util.UnaryPredicate;

import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;

/**
 * This class queries for IDMEF messages and keeps
 * an updated list of Sensors with the capability. All events
 * are copied the blackboard. You must provide the name of the
 * Society Security Manager, a UnaryPredicate class that
 * selects the IDMEF messages and a class name that supports the
 * QueryClassificationProvicer interface. A single class may support
 * both.<p>
 * For example, if you want to suppor login
 * failure rate calculation and user lockout, you would have the
 * following in your configuration:
 * <pre>
 * plugin = org.cougaar.core.security.monitorin.plugin.RateCalculatorPlugin(20,60,org.cougaar.core.security.monitoring.LOGIN_FAILURE,org.cougaar.core.security.monitoring.LOGIN_FAILURE_RATE)
 * plugin = org.cougaar.core.security.monitoring.plugin.UserLockoutPlugin(600,86400)
 * plugin = org.cougaar.core.security.monitoring.plugin.EventQueryPlugin(SocietySecurityManager,org.cougaar.core.security.monitoring.plugin.AllLoginFailures)
 * plugin = org.cougaar.lib.aggagent.plugin.AggregationPlugin
 * plugin = org.cougaar.lib.aggagent.plugin.AlertPlugin
 * </pre>
 */
public class EventQueryPlugin extends ComponentPlugin {
  private LoggingService  _log;

  /** the current agent's name */
  private String _agentName;

  private String _community;


  /** format script for the aggregation query */
  private static final ScriptSpec FORMAT_SPEC =
    new ScriptSpec(Language.JAVA, XmlFormat.INCREMENT, 
                   FormatEvent.class.getName());

  /** Aggregation query subscription */
  protected IncrementalSubscription _eventQuery;

  /** Sensor list update subscription */
  protected IncrementalSubscription _sensors;

  /** 
   * Results of the subscription are only going to belong to the 
   * a member of the _queryAdapters variable.
   */
  protected HashSet         _queryAdapters = null;

  /**
   * A set of agents that have the required sensor capabilities.
   */
  protected HashSet         _agents = null;

  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;

  /**
   * List of classifications to query
   */
  protected String         _classifications[];

  /**
   * Class used for choosing Events to retrieve
   */
  protected String         _unaryPredicateClass;

  /**
   * The predicate script for selecting which events to copy
   */
  protected ScriptSpec     _predSpec;

  /**
   * Society security manager agent. Default to "SocietySecurityManager".
   * This value can be set in the parameter.
   */
  private String _societySecurityManager = "SocietySecurityManager";

  /**
   * For parsing Alert events
   */
  private DocumentBuilderFactory _parserFactory = 
    DocumentBuilderFactory.newInstance();

  private UIDService _uidService = null;

  /**
   * Sensor update predicate
   */
  private static final UnaryPredicate SENSORS_PREDICATE = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof CmrRelay) {
          CmrRelay relay = (CmrRelay)o;
          if (relay.getContent() instanceof MRAgentLookUp &&
              relay.getResponse() != null) {
            return true;
          }
        }
        return false;
      }
    };

  /**
   * Used for determining if the query results have been updated.
   */
  private UnaryPredicate _eventPredicate =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        synchronized (_queryAdapters) {
          return (_queryAdapters.contains(o));
        }
      }
    };

  /**
   * Used for retrieving the persisting data
   */
  private final UnaryPredicate PERSIST_PREDICATE =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof EventQueryData) {
          EventQueryData eqd = (EventQueryData) o;
          if (eqd.unaryPredicateClass.equals(_unaryPredicateClass) &&
              eqd.classifications.length == _classifications.length) {
            for (int i = 0; i < _classifications.length; i++) {
              if (!eqd.classifications[i].equals(_classifications[i])) {
                return false;
              }
            }
            return true; // all classifications are the same
          }
        }
        return false;
      }
    };

  private EventQueryData _persistData;

  /**
   * Set the UID Service for use internally
   */
  public void setUIDService(UIDService uidService) {
    _uidService = uidService;
  }

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

  /**
   * creates the AggregationQuery for use in searching for
   * IDMEF messages
   */
  protected QueryResultAdapter createQuery() {
    AggregationQuery aq = new AggregationQuery(QueryType.PERSISTENT);
    aq.setName("Event Query");
    aq.setUpdateMethod(UpdateMethod.PUSH);
    aq.setPredicateSpec(_predSpec);
    aq.setFormatSpec(FORMAT_SPEC);
    QueryResultAdapter qra = new QueryResultAdapter(aq, _uidService.nextUID());
    qra.setResultSet(new EQAggregationResultSet());
    return qra;
  }

  public void setParameter(Object o) {
    System.out.println("setParameter called with: " + o);
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    Object[] arr = l.toArray();

    if (arr.length <= 1) {
      throw new IllegalArgumentException("You must provide the Society Security Manager name, and class names for the Unary Predicate and QueryClassificationProvider");
    }

    _societySecurityManager = (String) arr[0];
    if (_log == null && getServiceBroker() != null) {
      _log = (LoggingService)
        getServiceBroker().getService(this, LoggingService.class, null);
    }
    if (_log != null) {
      _log.info("Setting security manager agent name to " + _societySecurityManager);
    }
    _community = (String) arr[1];
    if (_community != null && _community.length() == 0) {
      _community = null;
    }
    QueryClassificationProvider qcp = null;
    String up = null;
    String className = "<not found>";
    try {
      for (int i = 2; i < arr.length; i++) {
        className = (String) arr[i];
        Class c = Class.forName(className);
        if (QueryClassificationProvider.class.isAssignableFrom(c)) {
          if (qcp != null) {
            if (!c.isInstance(qcp)) {
              throw new IllegalArgumentException("You may have only one " +
                                                 "QueryClasssificationProvider" +
                                                 " class in the " +
                                                 "EventQueryPlugin arguments");
            } // end of if (!c.isInstance(qcp))
          } else {
            qcp = (QueryClassificationProvider) c.newInstance();
          }
        }
        if (UnaryPredicate.class.isAssignableFrom(c)) {
          if (up != null) {
            if (!className.equals(up)) {
              throw new IllegalArgumentException("You may have only one " +
                                                 "UnaryPredicate" +
                                                 " class in the " +
                                                 "EventQueryPlugin arguments");
            } // end of if (!c.isInstance(up))
          } else {
            up = className;
          } // end of else
        } // end of if (UnaryPredicate.class.isAssignableFrom(c))
      } 
    } catch (IllegalAccessException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + 
                                         " could not be instantiated.");
    } catch (InstantiationException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + 
                                         " could not be instantiated.");
    } catch (ClassNotFoundException e) {
      throw new IllegalArgumentException("The class name you provided: " +
                                         className + " could not be found.");
    } // end of try-catch
    
    
    if (up == null) {
      throw new IllegalArgumentException("You must provide a class name that"
                                          + " implements the UnaryPredicate " +
                                          "interface");
    } // end of if (up == null)
    if (qcp == null) {
      throw new IllegalArgumentException("You must provide a class name" +
                                         "that implements the " + 
                                         "QueryClassificationProvider " +
                                         "interface");
    } // end of if (qcp == null)

    _unaryPredicateClass = up;
    _predSpec = new ScriptSpec(ScriptType.UNARY_PREDICATE, Language.JAVA, up);
    _classifications = qcp.getClassifications();
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);
    
    ServiceBroker        sb           = getBindingSite().getServiceBroker();
    DomainService        ds           = getDomainService(); 
    CmrFactory           cmrFactory   = (CmrFactory) ds.getFactory("cmr");
    IdmefMessageFactory  imessage     = cmrFactory.getIdmefMessageFactory();
    BlackboardService    bbs          = getBlackboardService();
    _agentName = ((AgentIdentificationService)
                  sb.getService(this, AgentIdentificationService.class, null)).getName();

    rehydrate();

    _eventQuery = (IncrementalSubscription)
      getBlackboardService().subscribe(_eventPredicate);

    _sensors = (IncrementalSubscription) 
      bbs.subscribe(SENSORS_PREDICATE);

    for (int i = 0 ; i < _classifications.length; i++) {
      Collection c = bbs.query(new MRAgentPredicate(_classifications[i]));
      if (!c.isEmpty()) {
        if (_log.isInfoEnabled()) {
          _log.info("MRAgentLookUp exists for " + _classifications[i]);
        } // end of if (_log.isInfoEnabled())
      } else {
        // need to create a lookup for this classification
        Classification classification = 
          imessage.createClassification(_classifications[i], null);
        MRAgentLookUp lookup = new MRAgentLookUp( _community, null, null, null,
                                                  classification, null, null, 
                                                  true );
        MessageAddress destination = 
          MessageAddress.getMessageAddress(_societySecurityManager);
        CmrRelay relay = cmrFactory.newCmrRelay(lookup, destination);
        bbs.publishAdd(relay);
        if (_log.isDebugEnabled()) {
          _log.debug("Searching for sensors using security manager cluster " +
                     "id: " + _societySecurityManager);
        }
      } // end of else
    } // end of for (int i = 0 ; i < classifications.length; i++)
  }

  /**
   * Picks up the persisted data and restores it to the local cache
   */
  protected void rehydrate() {
    BlackboardService bbs = getBlackboardService();
    Collection c = bbs.query(PERSIST_PREDICATE);
    if (c.isEmpty()) {
      UIDService uids = 
        (UIDService) getServiceBroker().getService(this,
                                                   UIDService.class,
                                                   null);
      _persistData = new EventQueryData();
      if (uids != null) {
        uids.registerUniqueObject(_persistData);
      }
      _agents = _persistData.agents = new HashSet();
      _queryAdapters = _persistData.queryAdapters = new HashSet();
      _persistData.classifications = _classifications;
      _persistData.unaryPredicateClass = _unaryPredicateClass;
      bbs.publishAdd(_persistData);
      _log.info("No rehydration.");
    } else {
      _persistData = (EventQueryData) c.iterator().next();
      _agents = _persistData.agents;
      _queryAdapters = _persistData.queryAdapters;
      bbs.publishChange(_persistData);
      _log.info("Rehydrating.");
    }
  }

  /**
   * Called whenever there is an update in the AggregationQuery results
   * or there is a change to the sensors.
   * Updates the count of events for the bucket associated with
   * the current second. 
   */
  public void execute() {
    if (_eventQuery.hasChanged()) {
      processEvents();
    }
    if (_sensors.hasChanged()) {
      updateSensors();
    }
  }

  /**
   * Copy the event to the blackboard
   */
  protected void processEvents() {
    Enumeration queryResults = _eventQuery.getChangedList();
    while (queryResults.hasMoreElements()) {
      QueryResultAdapter queryResult = 
        (QueryResultAdapter) queryResults.nextElement();
      EQAggregationResultSet results = 
        (EQAggregationResultSet) queryResult.getResultSet();
      if (results.exceptionThrown()) {
        _log.error("Exception when executing query: " + results.getExceptionSummary());
        _log.debug("XML: " + results.toXml());
      } else {
        Iterator atoms = results.getAddedAtoms();
        BlackboardService bbs = getBlackboardService();
        DocumentBuilder parser;
        try {
          parser = _parserFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
          _log.error("Can't parse any events. The parser factory isn't configured properly.");
          _log.debug("Configuration error.", e);
          return;
        }
        while (atoms.hasNext()) {
          ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
          String owner = d.getIdentifier("owner").toString();
          String id = d.getIdentifier("id").toString();
          String source = d.getValue("source").toString();
          String xml = d.getValue("event").toString();

          Event event = new EventImpl(new UID(owner,Long.parseLong(id)),
                                      MessageAddress.getMessageAddress(source),
                                      IDMEF_Message.createMessage(xml));
          
          bbs.publishAdd(event);
        }
      }
    }
  }

  /**
   * Updates the Aggregation Query to use the changed sensor capabilities list
   */
  private synchronized void updateSensors() {
    Enumeration e = _sensors.getChangedList();

    QueryResultAdapter qra = createQuery();
    AggregationQuery query = qra.getQuery();

    while (e.hasMoreElements()) {
      CmrRelay relay = (CmrRelay) e.nextElement();
      MRAgentLookUpReply reply = (MRAgentLookUpReply) relay.getResponse();
      List agents = reply.getAgentList();
      Iterator iter = agents.iterator();
      while (iter.hasNext()) {
        String agent = iter.next().toString();
        if (!_agents.contains(agent)) {
	  if (_log.isInfoEnabled()) {
	    _log.info("Added source sensor agent: " + agent);
	  }
          query.addSourceCluster(agent);
          _agents.add(agent);
        }
      }
    }

    if (!query.getSourceClusters().hasMoreElements()) {
      // nothing new
      return;
    }

    synchronized (_queryAdapters) {
      _queryAdapters.add(qra);
    }

    getBlackboardService().publishAdd(qra);
    getBlackboardService().publishChange(_persistData);
  }

  /**
   * This class extends AggregationResultSet to add newgetAddedAtoms() method.
   * Many thanks to Krishna Yallapu for this code.
   */
  public static class EQAggregationResultSet extends AggregationResultSet {
    List addedAtoms = new LinkedList();

    public void incrementalUpdate (UpdateDelta delta) {
      super.incrementalUpdate(delta);
      addedAtoms.addAll(delta.getAddedList());
    }

    public Iterator getAddedAtoms () {
      List addedList = new LinkedList();
      addedList.addAll(addedAtoms);
      Iterator iter = addedList.iterator();
      addedAtoms.clear();
      return iter;
    }
  }

  private static class MRAgentPredicate implements UnaryPredicate {
    String _cfn;

    public MRAgentPredicate(String classification) {
      _cfn = classification;
    }

    public boolean execute(Object o) {
      if (!(o instanceof CmrRelay)) {
        return false;
      } // end of if (!(o instanceof CmrRelay))
      CmrRelay cmr = (CmrRelay) o;
      Object content = cmr.getContent();
      if (!(content instanceof MRAgentLookUp)) {
        return false;
      } // end of if (!(content instanceof MRAgentLookUp))
      MRAgentLookUp mr = (MRAgentLookUp) content;
      return (_cfn.equals(mr.classification.getName()));
    }
  }
}
