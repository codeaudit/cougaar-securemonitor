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

// cougaar core classes
import org.cougaar.core.security.constants.IdmefClassifications;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.publisher.EventPublisher;
import org.cougaar.core.security.monitoring.publisher.IdmefEventPublisher;
import org.cougaar.core.service.ThreadService;

/**
 * This class must be placed in the Node ini file to allow
 * the AccessAgentProxy and MessageProtectionService to report message
 * failures. This class reports the sensor capabilities to the
 * enclave security manager.
 *
 * Add the following line to your Node ini file's Plugins section:
 * <pre>
 * plugin = org.cougaar.core.security.monitoring.plugin.MessageFailureSensor
 * </pre>
 * The plugin also takes an optional parameter indicating the role
 * of the security manager to report to. The default is "Manager".
 * The communities that the capabilities are sent to are all the ones that
 * this sensor belongs to.
 */
public class MessageFailureSensor extends SensorPlugin {
  private static final String[] CLASSIFICATIONS = {
    IdmefClassifications.MESSAGE_FAILURE
  };

  public void setThreadService(ThreadService ts) {
    _threadService = ts;
  }

  protected SensorInfo getSensorInfo() {
    if(_sensorInfo == null) {
      _sensorInfo = new MFSensorInfo();
    }
    return _sensorInfo;
  }

  protected String []getClassifications() {
    return CLASSIFICATIONS;
  }

  protected boolean agentIsTarget() {
    return true;
  }
   protected boolean agentIsSource() {
    return false;
  }


  /**
   * Register this sensor's capabilities, and initialize the services that need to
   * to publish message failure events to this plugin's blackboard.
   *
   */
  protected void setupSubscriptions() {
    super.setupSubscriptions();
    EventPublisher publisher =
      new IdmefEventPublisher(_blackboard, _scs, _cmrFactory,
                              _log, getSensorInfo(), _threadService);
    setPublisher(publisher);
    publishIDMEFEvent();
  }

  public static void publishEvent(FailureEvent event) {
    publishEvent(MessageFailureSensor.class, event);
  }

  private class MFSensorInfo implements SensorInfo {
    /**
    * Get the name of the sensor/anaylzer.
    *
    * @return the name of the sensor
    */
    public String getName(){
      return "MessageFailureSensor";
    }
    /**
    * Get the sensor manufacturer.
    *
    * @return the sensor manufacturer
    */
    public String getManufacturer(){
      return "CSI";
    }

    /**
    * Get the sensor model.
    *
    * @return the sensor model
    */
    public String getModel(){
      return "Cougaar Message Failure Sensor";
    }

    /**
    * Get the sensor version.
    *
    * @return the sensor version
    */
    public String getVersion(){
      return "1.0";
    }

    /**
    * Get the class of analyzer software and/or hardware.
    *
    * @return the sensor class
    */
    public String getAnalyzerClass(){
      return "Cougaar Security";
    }
  }

  private SensorInfo _sensorInfo;
  private ThreadService _threadService;
}
