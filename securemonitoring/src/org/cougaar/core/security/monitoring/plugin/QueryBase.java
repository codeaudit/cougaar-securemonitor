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
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.service.community.CommunityService;
import org.cougaar.core.security.util.CommunityServiceUtil;
import org.cougaar.core.security.util.CommunityServiceUtilListener;

import java.util.Set;

public abstract class QueryBase extends ComponentPlugin {
  protected DomainService domainService;
  protected CommunityService communityService;
  protected LoggingService loggingService;
  protected CommunityServiceUtil _csu;
  protected MessageAddress myAddress;
 
  protected  boolean _isRoot;
  protected boolean _rootReady;
  
  protected String enableMnR;
 
  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService ds) {
    domainService = ds;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
  
  /**
   * Used by the binding utility through reflection to set my CommunityService
   */
  public void setCommunityService(CommunityService cs) {
    communityService = cs;
  }

  /**
   * Used by the binding utility through reflection to get my CommunityService
   */
  public CommunityService getCommunityService() {
    return communityService;
  }
  
  public void setLoggingService(LoggingService ls) {
    loggingService = ls; 
  }
  
  public LoggingService getLoggingService() {
    return loggingService; 
  }

  protected boolean amIRoot() {
    return _isRoot;
  } 
  protected boolean isRootReady() {
    return _rootReady;
  } 

  protected void setupSubscriptions() {
     enableMnR = System.getProperty("org.cougaar.core.security.enableMnR");
    if (enableMnR != null) {
      loggingService.warn("MnR community service request test " + enableMnR);
    }

    if (myAddress == null) {
      myAddress = getAgentIdentifier();
      if(loggingService == null) {
        loggingService = (LoggingService)
          getServiceBroker().getService(this, LoggingService.class, null); 
      }
      _csu = new CommunityServiceUtil(getServiceBroker());
      if (enableMnR != null && enableMnR.equals("1")) {
        return;
      }
      _csu.amIRoot(new RootListener());
    }
  }

  

  protected class RootListener  implements Runnable, CommunityServiceUtilListener {
    public void getResponse(Set entities) {
      if (enableMnR != null && enableMnR.equals("2")) {
        return;
      }

      _isRoot = !(entities == null || entities.isEmpty());
      _rootReady = true;
      loggingService.info("The agent " + myAddress + " is root? " + _isRoot);
      ThreadService ts = (ThreadService)
        getServiceBroker().getService(this, ThreadService.class, null);
      ts.getThread(this, this).schedule(0);
      getServiceBroker().releaseService(this, ThreadService.class, ts);
    }

    public void run() {
      getBlackboardService().openTransaction();
      try {
         execute();
      } finally {
        getBlackboardService().closeTransaction();
      }
    }
  }
}
