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

package org.cougaar.core.security.monitoring.blackboard;

import org.cougaar.core.component.BindingSite;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.domain.DomainAdapter;
import org.cougaar.core.service.LoggingService;
import org.cougaar.planning.service.LDMService;
/**
 * Create a barebones CmrDomain.  We have our own Factory
 * The property to load this Domain is:<pre>
 *   -Dorg.cougaar.domain.cmr=org.cougaar.core.security.monitoring.blackboard.CmrDomain
 * </pre>
 **/
public class CmrDomain extends DomainAdapter {
  private static final String CMR_NAME = "cmr".intern();
  private ServiceBroker serviceBroker;
  private LoggingService log;
  private LDMService ldmService;

  public String getDomainName() {
    return CMR_NAME;
  }

  public CmrDomain() { }

  public void setLDMService(LDMService ldms) {
    ldmService = ldms;
  }

  // Could initialize constants used in the domain here, for example
  public void initialize() {
    super.initialize();
  }

  protected void loadFactory() {
    BindingSite bindingSite = getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain Factory without a binding site.");
    } 
    serviceBroker = bindingSite.getServiceBroker();
    log = (LoggingService)
      serviceBroker.getService(this,
			       LoggingService.class, null);
    if (log.isDebugEnabled()) {
      log.debug("cmr domain is loaded"); 
    }
    // if the ldmService is null get it from the servicebroker
    if(ldmService == null) {
      if(log.isDebugEnabled()) {
        log.debug("LDMService is null, trying to obtain LDMService through ServiceBroker");
      }
      ldmService = (LDMService)serviceBroker.getService(this, LDMService.class, null);
    }
    setFactory(new CmrFactory(ldmService.getLDM()));
  }
    
  // Here we say that we're just going to use the same basic
  // blackboard as everyone else.
  // You could create your own blackboard, but I'm honestly not
  // sure what's entailed with that, or what it buys you
  protected void loadXPlan() {
    // no cmr specific plan
    /*
    DomainBindingSite bindingSite = (DomainBindingSite) getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain XPlan without a binding site.");
    } 

    Collection xPlans = bindingSite.getXPlans();
    BlackboardServesDomain logPlan = null;
    
    for (Iterator iterator = xPlans.iterator(); iterator.hasNext();) {
      BlackboardServesDomain  xPlan = (BlackboardServesDomain) iterator.next();
      if (xPlan instanceof LogPlan) {
        // Note that this means there are 2 paths to the plan.
        // Is this okay?
        logPlan = xPlan;
        break;
      }
    }
    
    if (logPlan == null) {
      logPlan = new LogPlan();
    }
    
    setXPlan(logPlan);
    */
  }

  protected void loadLPs() {
    // no cmr domain LPs
   /*
    DomainBindingSite bindingSite = (DomainBindingSite) getBindingSite();

    if (bindingSite == null) {
      throw new RuntimeException("Binding site for the Cmr domain has not be set.\n" +
                             "Unable to initialize Cmr domain LPs without a binding site.");
    } 

    // Most LPs actually need a LogPlanServesLogicProvider. The only XPlan that implements
    // that (actually, the only one anywhere), is the LogPlan. So cast it.
    LogPlan logPlan = (LogPlan) getXPlan();

    //addLogicProvider(new ImpactsLP(logPlan, cluster));;
    */
  }

}
