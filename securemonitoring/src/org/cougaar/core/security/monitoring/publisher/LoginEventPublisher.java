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
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.event.EventClassification;
import org.cougaar.core.security.monitoring.event.LoginFailureEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;

import java.util.ArrayList;
import java.util.List;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;

public class LoginEventPublisher extends IdmefEventPublisher {

  public LoginEventPublisher(BlackboardService bbs, 
                             SecurityContextService scs, 
                             CmrFactory cmrFactory, 
                             LoggingService logger,
                             SensorInfo info, 
                             ThreadService ts) {
    super(bbs, scs, cmrFactory, logger, info, ts);
  }

  private List createClassifications() {
    ArrayList cfs = new ArrayList();
    cfs.add(EventClassification.LOGINFAILURE);
    return cfs;
  }

  private List createSources(String remoteAddr) {
    List addrs = new ArrayList();
    Address addr = _idmefFactory.createAddress( remoteAddr, null,
                                                Address.IPV4_ADDR );
    addrs.add(addr);
    IDMEF_Node node = _idmefFactory.createNode( null, addrs );

    Source src = _idmefFactory.createSource(node, null, null, null, null);

    List srcs = new ArrayList();
    srcs.add(src);
    return srcs;
  }

  private List createTargets(String url, int serverPort, String protocol,
                             String userName) {
    IDMEF_Node node = _idmefFactory.getNodeInfo();
    List addrs = new ArrayList();
    if (node.getAddresses() != null) {
      Address[] a = node.getAddresses();
      for (int i = 0; i < a.length; i++) {
        addrs.add(a[i]);
      } // end of for (int i = 0; i < a.length; i++)
    }

    addrs.add(_idmefFactory.createAddress(url, null, Address.URL_ADDR));

    node = _idmefFactory.createNode(node.getName(), addrs);

    IDMEF_Process process = _idmefFactory.getProcessInfo();
    Service service = _idmefFactory.createService("Cougaar Web Server",
                                                  new Integer(serverPort),
                                                  protocol);

    User user = null;
    List uids = new ArrayList();
    if (userName != null) {
      uids.add(_idmefFactory.createUserId( userName ));
    }
    if (uids.size() > 0) {
      user = _idmefFactory.createUser( uids );
    }
    Target target = _idmefFactory.createTarget(node, user, process, service,
                                               null, null);
    List targets = new ArrayList();
    targets.add(target);
    return targets;
  }

  private List createAdditionalData(String reason, String targetIdent,
                                    String data) {
    Agent agentinfo = _idmefFactory.getAgentInfo();
    String [] ref=null;
    if (agentinfo.getRefIdents()!=null) {
      String[] originalref=agentinfo.getRefIdents();
      ref=new String[originalref.length+1];
      System.arraycopy(originalref,0,ref,0,originalref.length);
      ref[originalref.length] = targetIdent;
    } else {
      ref=new String[1];
      ref[0] = targetIdent;
    }
    agentinfo.setRefIdents(ref);

    AdditionalData additionalData =
      _idmefFactory.createAdditionalData(Agent.TARGET_MEANING, agentinfo);
    List addData = new ArrayList();
    addData.add(_idmefFactory.
                createAdditionalData(AdditionalData.STRING, LoginFailureEvent.FAILURE_REASON,
                                     reason));
    addData.add(additionalData);
    if (data != null) {
      addData.add(_idmefFactory.
                  createAdditionalData(AdditionalData.STRING,
                                       "Exception", data));
    }
    return addData;
  }

  protected Event createIDMEFAlert(FailureEvent event){
    LoginFailureEvent loginEvent = (LoginFailureEvent)event;
    String remoteAddr = loginEvent.getEventSource()[0];
    String [] eventTargets = loginEvent.getEventTarget();
    String url = eventTargets[0];
    int serverPort = 0;
    try {
      serverPort = Integer.parseInt(eventTargets[1]);
    } 
    catch (Exception ex) {
      if( _logger.isWarnEnabled()){
        _logger.warn("Error in getting server port no :"+ ex.getMessage());
      }
    }
    String protocol = eventTargets[2];
    String userName = eventTargets[3];

    List sources = createSources(remoteAddr);
    List targets = createTargets(url, serverPort, protocol,
                                 userName);
    List classifications = createClassifications();
    String targetIdent = ((Target) targets.get(0)).getIdent();
    List additionalData = createAdditionalData(
      event.getReason(), targetIdent,
      event.getDataIdentifier());
    Alert alert = _idmefFactory.createAlert(_sensorInfo, new DetectTime(),
                                            sources, targets,
                                            classifications,
                                            additionalData);

    return _cmrFactory.newEvent(alert);
  }
}
