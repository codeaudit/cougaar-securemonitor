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
import org.cougaar.core.security.auth.ExecutionContext;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.event.FailureEvent;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.services.auth.SecurityContextService;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;

/*
//for debugging purposes
import org.w3c.dom.Document;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
*/

/**
 * class to generate and publish IDMEF messages based on
 * FailureEvents.
 *
 * @see FailureEvents
 * @see MessageFailureSensor
 * @see DataProtectionSensor
 */
public class IdmefEventPublisher implements EventPublisher {

  /**
   * Constructor
   */
  public IdmefEventPublisher(BlackboardService bbs, 
                             SecurityContextService scs, 
                             CmrFactory cmrFactory, 
                             LoggingService logger, 
                             SensorInfo info,
                             ThreadService ts) {
    _blackboard = bbs;
    _scs = scs;
    _logger = logger;
    _cmrFactory = cmrFactory;
    _idmefFactory = _cmrFactory.getIdmefMessageFactory();
    _sensorInfo = info;
    // get the sensor's execution context
    _ec = _scs.getExecutionContext();
    _threadService = ts;
  }
  
  /**
   * method to publish an IDMEF message based on the events in the Collection.
   *
   * @param events a collection of events to publish as IDMEF messages
   */
  public void publishEvents(List events) {
    if((events == null ||
        events.size() == 0)){
      if(_logger != null) {
        _logger.warn("event list is empty!");
      }
      return;
    }
    Iterator i = events.iterator();
    while(i.hasNext()) {
      publishEvent((FailureEvent)i.next());
    }
  }

  /**
   * method to publish an IDMEF message based on the event
   *
   * @param event a failure event
   */
  public void publishEvent(final FailureEvent event) {
    //boolean openTransaction = false;
    if(event == null){
      if(_logger != null) {
        _logger.warn("no event to publish!");
      }
      return;
    }
		
    if(_blackboard != null) {
      if(_logger.isDebugEnabled()) {
        _logger.debug("publishing message failure:\n" + event);
      }
      //openTransaction= _blackboard.isTransactionOpen();
      //if(!openTransaction) {
      Runnable publishIt = new Runnable() {
          public void run() {
            _blackboard.openTransaction();
            _blackboard.publishAdd(createIDMEFAlert(event));
            _blackboard.closeTransaction();
          }
        };
      _scs.setExecutionContext(_ec);
      Schedulable s = _threadService.getThread(this, publishIt);
      s.start();
      _scs.resetExecutionContext();
    }
  }

  /**
   * private method to create an M&R domain objects
   */
  protected Event createIDMEFAlert(FailureEvent event){
    List sources = null;
    List targets = null;
    List classifications = new ArrayList(1);
    List data = new ArrayList();
    Source s = null;
    Target t = null;
    Agent sAgent = null;
    Agent tAgent = null;

    String src = event.getSource();
    String tgt = event.getTarget();

    // create source information for the IDMEF event
    if(src != null) {
      List sRefList = new ArrayList(1);
      Address sAddr = _idmefFactory.createAddress(src, null, Address.URL_ADDR);
      sources = new ArrayList(1);
      s = _idmefFactory.createSource(null, null, null, null, null);
      sRefList.add(s.getIdent());
      sAgent = _idmefFactory.createAgent(src, null, null, sAddr, sRefList);
      sources.add(s);
    }
    // create target information for the IDMEF event
    if(tgt != null) {
      List tRefList = new ArrayList(1);
      Address tAddr = _idmefFactory.createAddress(tgt, null, Address.URL_ADDR);
      targets = new ArrayList(1);
      t = _idmefFactory.createTarget(null, null, null, null, null, null);
      tRefList.add(t.getIdent());
      tAgent = _idmefFactory.createAgent(tgt, null, null, tAddr, tRefList);
      targets.add(t);
    }
    // add the event classification to the classification list
    classifications.add(_idmefFactory.createClassification(event.getClassification(), null));
    String reason = event.getReason();
    String evtData = event.getData();
    if(reason != null) {
      data.add(_idmefFactory.createAdditionalData(AdditionalData.STRING,
                                                  event.getReasonIdentifier(),
                                                  event.getReason()));
    }
    if(evtData != null) {
      data.add(_idmefFactory.createAdditionalData(AdditionalData.STRING,
                                                  event.getDataIdentifier(),
                                                  event.getData()));
    }
    // since there isn't a data model for cougaar Agents, the Agent object is
    // added to the AdditionalData of an IDMEF message
    if(sAgent != null) {
      data.add(_idmefFactory.createAdditionalData(Agent.SOURCE_MEANING, sAgent));
    }
    if(tAgent != null) {
      data.add(_idmefFactory.createAdditionalData(Agent.TARGET_MEANING, tAgent));
    }
    // check if any data has been added to the additional data
    if(data.size() == 0) {
      data = null;
    }
    DetectTime dt = new DetectTime();
    dt.setIdmefDate(event.getDetectTime());
    dt.setNtpstamp(event.getDetectTime());

    // create the alert for this event
    Alert alert = _idmefFactory.createAlert(_sensorInfo,
                                            dt,
                                            sources,
                                            targets,
                                            classifications,
                                            data);
    /*
      if(_logger.isDebugEnabled()) {
      try {
      _logger.debug("Alert in XML format:\n");
      DocumentBuilder _docBuilder =
      DocumentBuilderFactory.newInstance().newDocumentBuilder();
      Document document = _docBuilder.newDocument();
      document.appendChild(alert.convertToXML(document));
      _logger.debug(XMLUtils.doc2String(document));
      }
      catch( Exception e ){
      e.printStackTrace();
      }
      }
    */
    return _cmrFactory.newEvent(alert);
  }

  // service needed to publish idmef messages
  protected BlackboardService _blackboard = null;
  // service used to track the security context
  protected SecurityContextService _scs = null;
  // service needed to do some appropriate logging
  protected LoggingService _logger = null;
  // factory used to create events that are published to the blackboard
  protected CmrFactory _cmrFactory = null;
  // factory used to create idmef objects
  protected IdmefMessageFactory _idmefFactory = null;
  protected SensorInfo _sensorInfo = null;
  protected ThreadService _threadService = null;
  private final ExecutionContext _ec;
}
 
