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


import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Collection;
import java.util.Iterator;
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mobility.AbstractTicket;
import org.cougaar.core.mobility.RemoveTicket;
import org.cougaar.core.mobility.ldm.AgentControl;
import org.cougaar.core.mobility.ldm.MobilityFactory;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.constants.BlackboardCompromise;
import org.cougaar.core.security.crypto.CertificateType;
import org.cougaar.core.security.crypto.CertificateUtility;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.policy.CryptoClientPolicy;
import org.cougaar.core.security.policy.PersistenceManagerPolicy;
import org.cougaar.core.security.policy.SecurityPolicy;
import org.cougaar.core.security.policy.TrustedCaPolicy;
import org.cougaar.core.security.services.crypto.KeyRingService;
import org.cougaar.core.security.services.util.ConfigParserService;
import org.cougaar.core.security.services.util.PersistenceMgrPolicyService;
import org.cougaar.core.security.coordinator.AgentCompromiseInfo;
import org.cougaar.core.security.util.SharedDataRelay;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.UIDService;
import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.plan.AllocationResult;
import org.cougaar.planning.ldm.plan.AspectType;
import org.cougaar.planning.ldm.plan.AspectValue;
import org.cougaar.planning.ldm.plan.Constraint;
import org.cougaar.planning.ldm.plan.Disposition;
import org.cougaar.planning.ldm.plan.Expansion;
import org.cougaar.planning.ldm.plan.NewConstraint;
import org.cougaar.planning.ldm.plan.NewPrepositionalPhrase;
import org.cougaar.planning.ldm.plan.NewTask;
import org.cougaar.planning.ldm.plan.NewWorkflow;
import org.cougaar.planning.ldm.plan.PrepositionalPhrase;
import org.cougaar.planning.ldm.plan.Task;
import org.cougaar.planning.ldm.plan.Verb;
import org.cougaar.planning.ldm.plan.Workflow;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;


/**
 * Subscribes to IDMEF Events identifiying a compromised agent, node or host
 * Not using the relays to the Ca, instead using the url, for some reason, the
 * relays are not showing up on the ca??
 *
 * @author ttschampel
 */
public class MnrCompromisePlugin extends ComponentPlugin {
  /** Plugin name */
  private static final String pluginName = "MnrCompromisePlugin";
  private static final String RECOVER_VERB = "RecoverFromFailure";
  private static final String REVOKE_SESSION_KEYS_VERB = BlackboardCompromise.REVOKE_SESSION_KEY_VERB;
  private static final String REVOKE_AGENT_CERT_VERB = BlackboardCompromise.REVOKE_AGENT_CERT_VERB;
  
/** Subscription to recover tasks */
  private IncrementalSubscription recoverTasks = null;
  /** Predicate for Recover Tasks */
  private UnaryPredicate recoverPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Task) {
          Task t = (Task) o;
          return (t.getVerb() != null)
            && (t.getVerb().toString().equals(REVOKE_SESSION_KEYS_VERB)
                || t.getVerb().toString().equals(REVOKE_AGENT_CERT_VERB));
        }

        return false;
      }
    };

  /** Subscription to "Done" revoke session key relays */
  private IncrementalSubscription remoteAgentDoneSubs = null;
  /** Predicate for "done" revoke session key relays */
  private UnaryPredicate removeAgentDonePredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof SharedDataRelay) {
          SharedDataRelay sdr = (SharedDataRelay) o;
          if ((sdr.getResponse() != null)
              && sdr.getResponse() instanceof Task) {
            Task t = (Task) sdr.getResponse();
            return (t.getVerb() != null)
              && (t.getVerb().toString().equals(REVOKE_SESSION_KEYS_VERB)
                  || t.getVerb().toString().equals(REVOKE_AGENT_CERT_VERB));
          }
        }

        return false;
      }
    };

  /** Communication between this component and AgentCompromise coordinator */
  private IncrementalSubscription coordinatorSubs = null;
  /** Predicate for coordinator */
  private UnaryPredicate coordinatorPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof AgentCompromiseInfo) {
        AgentCompromiseInfo info = (AgentCompromiseInfo)o;
        return info.getType().equals(AgentCompromiseInfo.ACTION);
      }
      return false;
    }
  };
 
  private UnaryPredicate diagnosisPredicate = new UnaryPredicate() {
    public boolean execute(Object o) {
      if (o instanceof AgentCompromiseInfo) {
        return ((AgentCompromiseInfo)o).getType().equals(AgentCompromiseInfo.SENSOR);
      }
      return false;
    }
  };

/** UIDService */
  private UIDService uidService = null;
  /** Domain Service */
  private DomainService domainService = null;
  private MobilityFactory mobilityFactory;

  /** Logging Service */
  private LoggingService logging = null;
  /** Predicate to evenets */
  /*
  private UnaryPredicate eventPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Event) {
          Event event = (Event) o;
          if ((event.getEvent() != null)
              && event.getEvent() instanceof Alert) {
            Alert alert = (Alert) event.getEvent();
            if (alert.getClassifications() != null) {
              Classification[] classifications = alert
                .getClassifications();
              for (int i = 0; i < classifications.length; i++) {
                if ((classifications[i].getName() != null)
                    && classifications[i].getName().equals(CompromiseBlackboard.CLASSIFICATION)) {
                  return true;
                }
              }
            }
          }
        }

        return false;
      }
    };
  */

  private IncrementalSubscription unpackSubs = null;
  private UnaryPredicate unpackPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof SharedDataRelay) {
          SharedDataRelay sdr = (SharedDataRelay) o;
          return (sdr.getContent() != null)
            && sdr.getContent() instanceof Event;
        }

        return false;
      }
    };

  private IncrementalSubscription finishedTaskSubs = null;
  private UnaryPredicate finshedPredicate = new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof Disposition) {
          Disposition d = (Disposition) o;
          Task t = d.getTask();
          return (t.getVerb() != null)
            & (t.getVerb().toString().equals(BlackboardCompromise.REVOKE_AGENT_CERT_VERB)
               || t.getVerb().toString().equals(BlackboardCompromise.REVOKE_SESSION_KEY_VERB));
        }

        return false;
      }
    };

/*
  private static final UnaryPredicate BLACKBOARD_COMPROMISE_PREDICATE =
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
          OperatingMode om = (OperatingMode) o;
          String omName = om.getName();
          if (BLACKBOARD_FAILURE_COUNT.equals(omName)) {
            return true;
          }
        }
        return false;
      }
    };
*/

  /** PersistenceMgrPolicyService */
  PersistenceMgrPolicyService pmPolicyService = null;

  /**
   * Set logging service
   *
   * @param service
   */
  public void setLoggingService(LoggingService service) {
    this.logging = service;
  }


  /**
   * Load component
   */
  public void load() {
    super.load();
    //load PersistenceMgrPolicyService
    pmPolicyService = (PersistenceMgrPolicyService) this.getServiceBroker()
      .getService(this,
                  PersistenceMgrPolicyService.class, null);
    if (pmPolicyService == null) {
      if (logging.isErrorEnabled()) {
        logging.error("PersistenceMgrPolicyService is null!");
      }
    }

    this.domainService = (DomainService) this.getServiceBroker().getService(this,
                                                                            DomainService.class, 
                                                                            null);
    this.uidService = (UIDService) this.getServiceBroker().getService(this,
                                                                      UIDService.class, 
                                                                      null);
    if (domainService != null) {
      mobilityFactory =
        (MobilityFactory) domainService.getFactory("mobility");
    }
    else {
      logging.warn("Cannot get mobility factory! Will not be able to remove compromised agent!");
    }
  }


  /**
   * Setup subscriptions
   */
  protected void setupSubscriptions() {
    //this.eventSubscription = (IncrementalSubscription) getBlackboardService()
    //                                                      .subscribe(eventPredicate);
    this.recoverTasks = (IncrementalSubscription) getBlackboardService()
      .subscribe(this.recoverPredicate);
    this.remoteAgentDoneSubs = (IncrementalSubscription) getBlackboardService()
      .subscribe(this.removeAgentDonePredicate);
    this.finishedTaskSubs = (IncrementalSubscription) getBlackboardService()
      .subscribe(this.finshedPredicate);
    this.unpackSubs = (IncrementalSubscription) getBlackboardService()
      .subscribe(this.unpackPredicate);

    this.coordinatorSubs = (IncrementalSubscription) getBlackboardService()
      .subscribe(this.coordinatorPredicate);
  }


  /**
   * Process Subscriptions
   */
  protected void execute() {
    if (logging.isDebugEnabled()) {
      logging.debug(pluginName + " executing");
    }

    checkForCompromises();
    checkForCoordinatorAction();
    //check for pm && ca related tasks
    checkForNewTasks();
    checkForCompletedTasks();


    //Check for completed tasks to move to next one 
    checkForFinishedTasks();
    //checkForCompletedProcesses();
  }

  /**
   * Check for coordinator action
   */
  private void checkForCoordinatorAction() {
    Enumeration enumeration = coordinatorSubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      AgentCompromiseInfo info = (AgentCompromiseInfo)enumeration.nextElement();
      resolveCompromises(CompromiseBlackboard.AGENT_COMPROMISE_TYPE,
        info.getTimestamp(), info.getSourceHost(), 
        info.getSourceNode(), info.getSourceAgent());
      getBlackboardService().publishRemove(info);
    }
  }

  /**
   * Check for fully completed tasks and move to next one in workflow
   */
  private void checkForFinishedTasks() {
    Enumeration enumeration = finishedTaskSubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      Disposition disp = (Disposition) enumeration.nextElement();
      Task t = disp.getTask();
      Workflow wf = t.getWorkflow();
      Constraint c = wf.getNextPendingConstraint();
      if (logging.isDebugEnabled()) {
        logging.debug("Next constraint:" + c);
      }

      if (c != null) {
        Task nexttask = c.getConstrainedTask();
        if (nexttask.getPlanElement() != null) {
          getBlackboardService().publishRemove(nexttask.getWorkflow()
                                               .getParentTask());
        } else {
          getBlackboardService().publishAdd(nexttask);
        }
      }
    }
  }


  /**
   * Check for revoke session key complete from PersistenceManager or revoke
   * agent cert from CA
   */
  private void checkForCompletedTasks() {
    Enumeration enumeration = remoteAgentDoneSubs.getChangedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      Task task = (Task) sdr.getContent();

      if (logging.isDebugEnabled()) {
        if (task.getVerb().toString().equals(REVOKE_SESSION_KEYS_VERB)) {
          logging.debug("PersistenceManager finished " + task);
        } else if (task.getVerb().toString().equals(REVOKE_AGENT_CERT_VERB)) {
          logging.debug("CA finished " + task);
        }
      }

      // check for coordinator action
      if (task.getVerb().toString().equals(REVOKE_AGENT_CERT_VERB)) {
        String coordinatorOn = System.getProperty("org.cougaar.core.security.coordinatorOn");
        if (coordinatorOn != null && coordinatorOn.equalsIgnoreCase("true")) {
          // signal compromise to AgentCompromiseSensor
          // sendDiagnosis
          if (logging.isDebugEnabled()) {
            logging.debug("Informing coordinator that agent restart completed.");
          }

          PrepositionalPhrase pp = task.getPrepositionalPhrase(BlackboardCompromise.FOR_AGENT_PREP);
          String agent = (String) pp.getIndirectObject();
          AgentCompromiseInfo info = new AgentCompromiseInfo(
          AgentCompromiseInfo.COMPLETION_CODE, agent, AgentCompromiseInfo.COMPLETED);
          getBlackboardService().publishAdd(info);
        }
      }

      try {
        getBlackboardService().publishRemove(sdr);

        PlanningFactory ldm = (PlanningFactory) domainService.getFactory(
          "planning");
        AspectValue[] values = new AspectValue[1];
        values[0] = AspectValue.newAspectValue(AspectType.END_TIME,
                                             (double) System.currentTimeMillis());
        AllocationResult allocResult = ldm.newAllocationResult(1.0, true,
                                                             values);
        Disposition disp = ldm.createDisposition(task.getPlan(), task,
                                               allocResult);
        getBlackboardService().publishAdd(disp);
      }
      catch (Exception ex) {
        logging.warn("Exception for adding disposition: " + ex);
        logging.warn("The disposition may already been published, this is the case for multiple CA and PM");
      }
    }
  }


  /**
   * Check for newly added Tasks added to blackboard
   */
  private void checkForNewTasks() {
    Enumeration enumeration = recoverTasks.getAddedList();
    while (enumeration.hasMoreElements()) {
      Task theTask = (Task) enumeration.nextElement();
      PrepositionalPhrase pp = theTask.getPrepositionalPhrase(BlackboardCompromise.FOR_AGENT_PREP);
      String agent = (String) pp.getIndirectObject();
      PrepositionalPhrase pp2 = theTask.getPrepositionalPhrase(BlackboardCompromise.COMPROMISE_TIMESTAMP_PREP);
      if (theTask.getVerb().toString().equals(REVOKE_SESSION_KEYS_VERB)) {
        long timestamp = ((Long) pp2.getIndirectObject()).longValue();
        if (logging.isDebugEnabled()) {
          logging.debug(
            "Send message to PersistenceManager to revoke session key for "
            + agent + " for compromise at " + new Date(timestamp));
        }


        //Get Location of PersitenceManager
        PersistenceManagerPolicy[] pmPolicies = pmPolicyService
          .getPolicies();
        if (logging.isDebugEnabled()) {
          logging.debug("Policy size:" + pmPolicies.length);
        }

        String pmAgentName = null;
        for (int i = 0; i < pmPolicies.length; i++) {
          PersistenceManagerPolicy pmPolicy = pmPolicies[i];
          if (logging.isDebugEnabled()) {
            logging.debug(pmPolicy.pmDN + ":" + pmPolicy.pmUrl
                          + ":" + pmPolicy.getName());
          }

          //get agent name from url
          String temp = pmPolicy.pmUrl.substring(pmPolicy.pmUrl
                                                 .indexOf("$") + 1, pmPolicy.pmUrl.length());
          pmAgentName = temp.substring(0, temp.indexOf("/"));

          if (logging.isDebugEnabled()) {
            logging.debug(
              "Sending revoke session key for agent relay to PersistenceManger at agent:"
              + pmAgentName);
          }

          MessageAddress source = this.getAgentIdentifier();
          MessageAddress target = MessageAddress.getMessageAddress(pmAgentName);
          SharedDataRelay relay = new SharedDataRelay(uidService
                                                      .nextUID(), source, target, theTask, null);
          getBlackboardService().publishAdd(relay);

        }
      } else {
        if (logging.isDebugEnabled()) {
          logging.debug(
            "Send message to CA to revoke agent cert for " + agent);
        }


        //Get CA info
        //for now end to caAgent
        MessageAddress source = this.getAgentIdentifier();
        CryptoClientPolicy policy = getCryptoClientPolicy();
        if (policy == null) {
          if (logging.isErrorEnabled()) {
            logging.error("cryptoClientPolicy is null");
          }
        }

        //TODO : Use SharedDataRelay again, for now using URL.
        TrustedCaPolicy[] trustedCaPolicy = policy.getTrustedCaPolicy();
        for (int i = 0; i < trustedCaPolicy.length; i++) {
          String caURL = trustedCaPolicy[i].caURL;

          if (caURL != null) {
            String caAgent = caURL.substring(caURL.indexOf("$")+1, caURL.length());
            caAgent = caAgent.substring(0, caAgent.indexOf("/"));
						
            String revokeCertServletURL = caURL.substring(0,
                                                          caURL.lastIndexOf('/'))
              + "/RevokeCertificateServlet";
                        
                        
            if (logging.isDebugEnabled()) {
              logging.debug(revokeCertServletURL);
              logging.debug("Compromised Agent's CA:" + caAgent);
            }
/**
   try {
   URL url = new URL(revokeCertServletURL);
   HttpURLConnection huc = (HttpURLConnection) url
   .openConnection();

   // Don't follow redirects automatically.
   huc.setInstanceFollowRedirects(false);
   // Let the system know that we want to do output
   huc.setDoOutput(true);
   // Let the system know that we want to do input
   huc.setDoInput(true);
   // No caching, we want the real thing
   huc.setUseCaches(false);
   // Specify the content type
   huc.setRequestProperty("Content-Type",
   "application/x-www-form-urlencoded");
   huc.setRequestMethod("POST");
   PrintWriter out = new PrintWriter(huc
   .getOutputStream());
   StringBuffer sb = new StringBuffer();
   sb.append("agent_name=");
   sb.append(URLEncoder.encode(agent, "UTF-8"));
   sb.append("&revoke_type=agent");
   sb.append("&ca_dn=");
   sb.append(URLEncoder.encode(caDn, "UTF-8"));
   out.println(sb.toString());
   out.flush();
   out.close();
   //complete task
   PlanningFactory ldm = (PlanningFactory) domainService
   .getFactory("planning");
   AspectValue[] values = new AspectValue[1];
   values[0] = AspectValue.newAspectValue(AspectType.END_TIME,
   (double) System.currentTimeMillis());
   AllocationResult allocResult = ldm
   .newAllocationResult(1.0, true, values);
   Disposition disp = ldm.createDisposition(theTask
   .getPlan(), theTask, allocResult);
   getBlackboardService().publishAdd(disp);
   } catch (Exception e) {
   if (logging.isErrorEnabled()) {
   logging.error("Error revoking cert", e);
   }
   }*/
                        
            MessageAddress target = MessageAddress
              .getMessageAddress(caAgent);
            SharedDataRelay relay = new SharedDataRelay(uidService
                                                        .nextUID(), source, target, theTask, null);
            getBlackboardService().publishAdd(relay);
                        
          }
        }
      }
    }
  }


  /**
   * Check for compromises, if there are, create a workflow of tasks to
   * complete in order to act accordingly
   */
  private void checkForCompromises() {
    Enumeration enumeration = this.unpackSubs.getAddedList();
    while (enumeration.hasMoreElements()) {
      SharedDataRelay sdr = (SharedDataRelay) enumeration.nextElement();
      Event event = (Event) sdr.getContent();
      Alert alert = (Alert) event.getEvent();
      AdditionalData[] data = alert.getAdditionalData();
      String scope = null;
      long timestamp = 0;
      String sourceNode = null;
      String sourceAgent = null;
      String sourceHost = null;
      for (int i = 0; i < data.length; i++) {
        AdditionalData adata = data[i];
        String dType = adata.getMeaning();
        String dData = adata.getAdditionalData();
        if ((dType != null) && dType.equals("compromisedata")) {
          StringTokenizer tokenizer = new StringTokenizer(dData, ",");
          while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            String _type = token.substring(0, token.indexOf("="));
            String _value = token.substring(token.indexOf("=") + 1,
                                            token.length());
            if (_type.equals("scope")) {
              scope = _value;
            } else if (_type.equals("compromise timestamp")) {
              timestamp = Long.parseLong(_value);
            } else if (_type.equals("sourceAgent")) {
              sourceAgent = _value;
            } else if (_type.equals("sourceNode")) {
              sourceNode = _value;
            } else if (_type.equals("sourceHost")) {
              sourceHost = _value;
            }
          }
        }
      }

      if (logging.isDebugEnabled()) {
        logging.debug("Got compromise of scope :" + scope
                      + " and time :" + new Date(timestamp) + " from "
                      + sourceHost + ":" + sourceNode + ":" + sourceAgent);
      }

      if (scope == null) {
        if (logging.isDebugEnabled()) {
          logging.debug(
            "Received a compromise idmef event without a defined scope!");
        }
      } else {

        // playbook action

        // check for coordinator action
        String coordinatorOn = System.getProperty("org.cougaar.core.security.coordinatorOn");
        if (coordinatorOn != null && coordinatorOn.equalsIgnoreCase("true")) {
          // check if status already changed
          Collection c = getBlackboardService().query(diagnosisPredicate);
          Iterator it = c.iterator();
          String level = AgentCompromiseInfo.NONE;
          AgentCompromiseInfo info = null;
          while (it.hasNext()) {
            info = (AgentCompromiseInfo)it.next();
            if (sourceAgent.equals(info.getSourceAgent())) {
              level = info.getDiagnosis();
              break;
            }
          }

          if (level.equals(AgentCompromiseInfo.SEVERE)) {
            // already reach max.
                if (logging.isDebugEnabled()) {
                  logging.debug("Level already changed for diagnosis: " + info.getDiagnosis());
                }
            return;
          }
          if (level.equals(AgentCompromiseInfo.MODERATE)) {
            level = AgentCompromiseInfo.SEVERE;
              getBlackboardService().publishRemove(info);
          }
          else {
            level = AgentCompromiseInfo.MODERATE;
          }
          // signal compromise to AgentCompromiseSensor
          // sendDiagnosis
          if (info != null) {
            // keep the timestamp! It is the start of compromise
            timestamp = info.getTimestamp();
          }

              // change
          info = new AgentCompromiseInfo(AgentCompromiseInfo.SENSOR,
              timestamp, sourceAgent, sourceNode, sourceHost, level);

          getBlackboardService().publishAdd(info);
              if (logging.isDebugEnabled()) {
                logging.debug("Agent compromised action initialized for agent: " + sourceAgent + " level: " + level);
              }
          if (level.equals(AgentCompromiseInfo.NONE)) {
            logging.warn("Cannot find diagnosis for : " + sourceAgent);
          }
          
        }
        else {
          resolveCompromises(scope, timestamp, sourceHost, sourceNode, sourceAgent);
        }
      }
    }
  }

  private void resolveCompromises(
    String scope, long timestamp, String sourceHost, 
    String sourceNode, String sourceAgent) {
      if (logging.isDebugEnabled()) {
        logging.debug("Resolve compromise of scope :" + scope
                      + " and time :" + new Date(timestamp) + " from "
                      + sourceHost + ":" + sourceNode + ":" + sourceAgent);
      }

        ArrayList agentsToBeRevoked = new ArrayList();
        PlanningFactory ldm = (PlanningFactory) domainService
          .getFactory("planning");
        NewTask rootTask = ldm.newTask();
        rootTask.setVerb(Verb.getVerb(RECOVER_VERB));

        NewWorkflow nwf = ldm.newWorkflow();
        nwf.setParentTask(rootTask);

        AllocationResult estResult = null;
        if (scope.equals(CompromiseBlackboard.AGENT_COMPROMISE_TYPE)) {
          if (logging.isDebugEnabled()) {
            logging.debug("revoking agent only");
          }

          agentsToBeRevoked.add(sourceAgent);

          if (mobilityFactory != null) {
            if (logging.isDebugEnabled()) {
              logging.debug("removing " + sourceAgent + " on " + sourceNode);
            }
            removeAgent(sourceAgent, sourceNode);

          }
        } else if (scope.equals(
                     CompromiseBlackboard.NODE_COMPROMISE_TYPE)) {
          if (logging.isDebugEnabled()) {
            logging.debug("revoke all agents in node");
          }
        } else if (scope.equals(
                     CompromiseBlackboard.HOST_COMPROMISE_TYPE)) {
          if (logging.isDebugEnabled()) {
            logging.debug("revoke all agents on host");
          }
        }

        ArrayList taskList = new ArrayList();
        for (int i = 0; i < agentsToBeRevoked.size(); i++) {
          String agentName = (String) agentsToBeRevoked.get(i);
          NewPrepositionalPhrase npp = ldm.newPrepositionalPhrase();
          npp.setPreposition(BlackboardCompromise.FOR_AGENT_PREP);
          npp.setIndirectObject(agentName);
          NewPrepositionalPhrase npp2 = ldm.newPrepositionalPhrase();
          npp2.setPreposition(BlackboardCompromise.COMPROMISE_TIMESTAMP_PREP);
          npp2.setIndirectObject(new Long(timestamp));
          NewTask pmTask = ldm.newTask();
          pmTask.setWorkflow(nwf);
          pmTask.setParentTask(rootTask);
          pmTask.setVerb(Verb.getVerb(REVOKE_SESSION_KEYS_VERB));
          pmTask.addPrepositionalPhrase(npp);
          pmTask.addPrepositionalPhrase(npp2);
          nwf.addTask(pmTask);
          if (i == 0) {
            getBlackboardService().publishAdd(pmTask);
          }

          NewTask caTask = ldm.newTask();
          caTask.setWorkflow(nwf);
          caTask.setParentTask(rootTask);
          caTask.setVerb(Verb.getVerb(REVOKE_AGENT_CERT_VERB));
          caTask.addPrepositionalPhrase(npp);
          //Get caDN for this agent
          ArrayList caDNs = this.getCaDNs(agentName);
          NewPrepositionalPhrase caPrep = ldm.newPrepositionalPhrase();
          caPrep.setPreposition(BlackboardCompromise.CA_DN_PREP);
          caPrep.setIndirectObject(caDNs);
          caTask.addPrepositionalPhrase(caPrep);
				
          nwf.addTask(caTask);
          taskList.add(pmTask);
          taskList.add(caTask);
        }

        Vector constraints = new Vector();
        for (int t = 0; t < taskList.size(); t++) {
          Task t1 = (Task) taskList.get(t);
          if ((t + 1) < taskList.size()) {
            Task t2 = (Task) taskList.get((t + 1));

            NewConstraint constraint = ldm.newConstraint();

            constraint.setConstrainingTask(t1);
            constraint.setConstrainingAspect(AspectType.END_TIME);
            constraint.setConstrainedTask(t2);
            constraint.setConstrainedAspect(AspectType.START_TIME);
            constraint.setConstraintOrder(Constraint.BEFORE);
            constraints.addElement(constraint);
          }
        }

        nwf.setConstraints(constraints.elements());

        Expansion exp = ldm.createExpansion(rootTask.getPlan(),
                                            rootTask, nwf, estResult);
        getBlackboardService().publishAdd(exp);
        getBlackboardService().publishAdd(rootTask);
  }


  /**
   * method that takes an action against the culprit
   *
   * @param agentName DOCUMENT ME!
   *
   * @return DOCUMENT ME!
   */
  protected ArrayList getCaDNs(String agentName) {
    ArrayList list = new ArrayList();
    CryptoClientPolicy policy = getCryptoClientPolicy();
    TrustedCaPolicy[] trustedCaPolicy = policy.getTrustedCaPolicy();
    for(int i=0;i<trustedCaPolicy.length;i++){
      list.add(trustedCaPolicy[i].caDN);
    }
    return list;
        
  }


  private String getCADN(X509Certificate[] certChain) {
    int len = certChain.length;
    String title = null;
    String dn = null;

    for (int i = 0; i < len; i++) {
      dn = certChain[i].getIssuerDN().getName();
      title = CertificateUtility.findAttribute(dn, "t");
      if (title.equals(CertificateType.CERT_TITLE_CA)) {
        return dn;
      }
    }

    return null;
  }


  private CryptoClientPolicy getCryptoClientPolicy() {
    CryptoClientPolicy cryptoClientPolicy = null;
    try {
      ConfigParserService configParserService = (ConfigParserService) this.getServiceBroker().
        getService(this,ConfigParserService.class, null);
      SecurityPolicy[] sp = configParserService.getSecurityPolicies(CryptoClientPolicy.class);
      cryptoClientPolicy = (CryptoClientPolicy) sp[0];
    } catch (Exception e) {
      if (logging.isErrorEnabled()) {
        logging.error("Can't obtain client crypto policy : "
                      + e.getMessage());
      }
    }

    return cryptoClientPolicy;
  }

  private AgentControl createAgentControl(
    UID ownerUID,
    MessageAddress target,
    AbstractTicket ticket) {
    if (mobilityFactory == null) {
      throw new RuntimeException(
        "Mobility factory (and domain) not enabled");
    }
    AgentControl ac =
      mobilityFactory.createAgentControl(
        ownerUID, target, ticket);
    return ac;
  }

  private void addAgentControl(AgentControl ac) {
/*
  try {
  getBlackboardService().openTransaction();
*/
    getBlackboardService().publishAdd(ac);
/*
  } finally {
  getBlackboardService().closeTransactionDontReset();
  }
*/
  }


  private void removeAgent(String agentName, String nodeName) {
    MessageAddress mobileAgentAddr = 
      MessageAddress.getMessageAddress(agentName);
    MessageAddress destNodeAddr =
      MessageAddress.getMessageAddress(nodeName);
    AbstractTicket ticket =
      new RemoveTicket(
        null,
        mobileAgentAddr,
        destNodeAddr);
    AgentControl ac = createAgentControl(
      null, destNodeAddr, ticket);
    addAgentControl(ac);
  }

}
