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


package org.cougaar.core.security.monitoring.publisher;

// cougaar core classes
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.EventClassification;
import org.cougaar.core.security.monitoring.event.SecurityExceptionEvent;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.DetectTime;


public class SecurityExceptionPublisher extends IdmefEventPublisher {

  public SecurityExceptionPublisher(BlackboardService bbs, SecurityContextService scs, 
    CmrFactory cmrFactory, LoggingService logger, SensorInfo info, ThreadService ts) {
    super(bbs, scs, cmrFactory, logger, info, ts);
  }

  private List createClassifications(String classification) {
    ArrayList cfs = new ArrayList();
    if(classification.equals(IdmefClassifications.SECURITY_MANAGER_EXCEPTION)) {
      cfs.add(EventClassification.SECURITY_MGR_EXCEPTION); 
    }
    else {
      cfs.add(EventClassification.JAR_VERIFY_FAILURE); 
    }
    return cfs;
  }

  protected Event createIDMEFAlert(FailureEvent event) {
    if(event == null || !(event instanceof SecurityExceptionEvent)) {
      return null;
    }
    
    SecurityExceptionEvent see = (SecurityExceptionEvent)event;
    Principal [] principals = see.getPrincipals();
    String stackTrace = see.getStackTrace();
    ArrayList additionalData = new ArrayList();
    
    if(principals != null) {
      // add the principal information to the additionalData
   	  for(int i = 0; i < principals.length; i++) {
        AdditionalData data = _idmefFactory.createAdditionalData(AdditionalData.STRING, 
                                                                 SecurityExceptionEvent.PRINCIPAL_ID, 
                                                                 principals[i].toString());
        additionalData.add(data);
      }
    }
    
    if(stackTrace != null ){
      // add the stack trace to the additionalData
     	AdditionalData data = _idmefFactory.createAdditionalData(AdditionalData.STRING, 
     	                                                         SecurityExceptionEvent.STACKTRACE_ID, 
     	                                                         stackTrace);
    	additionalData.add(data);
    }
    DetectTime dt = new DetectTime();
    dt.setIdmefDate(see.getDetectTime());
    dt.setNtpstamp(see.getDetectTime());
    Alert alert = _idmefFactory.createAlert(_sensorInfo, 
                                            dt, // get the event detect time
                                            null, // source is null for now
                                            null, // target is null for now
                                            createClassifications(see.getClassification()),
                                            additionalData);
    return _cmrFactory.newEvent(alert); 
  }
  
}
