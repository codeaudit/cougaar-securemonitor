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

import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.publisher.LoginEventPublisher;
import org.cougaar.core.service.ThreadService;

import java.util.List;

/**
 * This class must be placed in the Node ini file to allow
 * Tomcat to report login failures. This class reports the sensor
 * capabilities to the enclave security manager.
 * Add the following line to your Node ini file's Plugins section:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.LoginFailureSensor
 * </pre>
 * The plugin also takes an optional parameter indicating the role
 * of the security manager to report to. The default is "SecurityMnRManager".
 * The communities that the capabilities are sent to are all the ones that
 * this sensor belongs to.
 */
public class LoginFailureSensor extends SensorPlugin {
 
  private String         _managerRole   = "Manager";

  private final  String[] CLASSIFICATIONS = {IdmefClassifications.LOGIN_FAILURE};
  private SensorInfo  sensor=null;
  private ThreadService _threadService;
  public LoginFailureSensor() {
  }

  public void setThreadService(ThreadService ts) {
    _threadService = ts;
  }

  /**
   * Sets the role to report capabilities to.
   */
  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List argument to setParameter");
    }
    List l = (List) o;
    if (l.size() > 1) {
      throw new IllegalArgumentException("Unexpected number of parameters given. Expecting 1, got " + l.size());
    }
    if (l.size() > 0) {
      _managerRole = l.get(0).toString();
    }
  }



   protected SensorInfo getSensorInfo() {
    if(sensor == null) {
      sensor = new LFSensor();
    }
    return sensor;
  }

  protected  String []getClassifications() {
    return CLASSIFICATIONS;

  }

  protected  boolean agentIsTarget() {
    return true;
  }

  protected  boolean agentIsSource() {
    return false;

  }

  public static void publishEvent(FailureEvent event) {
    publishEvent(LoginFailureSensor.class, event);
  }

  /**
   * Assigns the agent's service broker to the KeyRingJNDIRealm so that
   * login failures can be reported with the IDMEF service.
   */
  protected void setupSubscriptions() {

    super.setupSubscriptions();

    if ( _log.isInfoEnabled()) {
      _log.info("Setting Security Manager role to " + _managerRole);
    }
    
    EventPublisher publisher =
      new LoginEventPublisher(_blackboard, _scs, _cmrFactory, _log, getSensorInfo(), _threadService);
    setPublisher(publisher);
    publishIDMEFEvent();
  }




  /**
   * Dummy function doesn't do anything. No subscriptions are made.
   */
  protected void execute () {
  }

  private static class LFSensor implements SensorInfo {

    public String getName() {
      return "Login Failure Sensor";
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
      return "org.cougaar.core.security.crypto.ldap.KeyRingJNDIRealm";
    }
  }
}
