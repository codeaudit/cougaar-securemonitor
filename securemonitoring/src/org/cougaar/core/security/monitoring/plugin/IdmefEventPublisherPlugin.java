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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.Agent;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.service.EventService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLSerializable;

public class IdmefEventPublisherPlugin
extends ComponentPlugin
{
  private IncrementalSubscription _idmefevents;
  private LoggingService _log;
  private EventService _eventService;
  private HashMap _eventCache = new HashMap();
  private int _cacheSize = 100;
  private int _cacheInterval = 6000;

  /**
   * A predicate that matches all "Event object which is not registration "
   */
  class IdemfEventPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      if (o instanceof Event) {
        IDMEF_Message msg = ((Event) o).getEvent();
        if (msg instanceof Registration ||
            msg instanceof AgentRegistration) {
          return false;
        }
        return (msg instanceof Alert);
      }
      /*
        if (o instanceof Event ) {
        Event e=(Event)o;
        IDMEF_Message msg=e.getEvent();
        if(msg instanceof Registration){
        return false;
        }
        else if(msg instanceof AgentRegistration) {
        return false;
        }
        Alert a = (Alert)msg; 
        Classification []cls = a.getClassifications();
        for(int i = 0; i < cls.length; i++) {
        if(cls[i].getName().equals(IdmefClassifications.LOGIN_FAILURE)) {
        return true;
        }
        }
        }
      */
      return false;
    }
  }

 
  protected void setupSubscriptions() {
    try {
      String propString = System.getProperty("org.cougaar.core.security.idmef.eventsize");
      _cacheSize = Integer.parseInt(propString);
      propString = System.getProperty("org.cougaar.core.security.idmef.interval");
      _cacheInterval = Integer.parseInt(propString);
    } catch (Exception ex) {}
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    _eventService = (EventService)getBindingSite().getServiceBroker().getService
      (this, EventService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("IdmefEventPublisherPlugin setupSubscription()");
    }
    _idmefevents = (IncrementalSubscription)
      getBlackboardService().subscribe(new IdemfEventPredicate());
  }
  
  protected void execute () {
    Collection eventcollection = _idmefevents.getAddedCollection();
    Iterator eventiterator = eventcollection.iterator();
    if (_eventService.isEventEnabled()) {
      while(eventiterator.hasNext()) {
        Event foo=(Event)eventiterator.next();
        Alert event = (Alert) foo.getEvent();
// 	Alert event=(Alert)eventiterator.next();
        StringBuffer s = new StringBuffer("[STATUS] IDMEF(");
        StringBuffer s2 = new StringBuffer();
        s.append(agentId.toAddress()).append(')');

        Classification cs[] = event.getClassifications();
        if (cs != null && cs.length != 0) {
          s.append(" Classification(");
          s2.append("Classification(");
          for (int i = 0; i < cs.length; i++) {
            if (i != 0) {
              s.append(',');
              s2.append(',');
            }
            s.append(cs[i].getName());
          }
          s.append(')');
          s2.append(')');
        }
        Source [] srcs = event.getSources();
        if (srcs != null && srcs.length != 0) {
          s.append(" Source(");
          for (int i = 0; i < srcs.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(srcs[i].getIdent());
            IDMEF_Node node = srcs[i].getNode();
            if (node != null) {
              Address [] addrs = node.getAddresses();
              if (addrs.length != 0) {
                s.append(':');
                s.append(addrs[0].getAddress());
              }
            }
          }
          s.append(')');
        }

        Target [] tgts = event.getTargets();
        if (tgts != null && tgts.length != 0) {
          s.append(" Target(");
          for (int i = 0; i < tgts.length; i++) {
            if (i != 0) {
              s.append(',');
            }
            s.append(tgts[i].getIdent());
            IDMEF_Node node = tgts[i].getNode(); 
            if (node != null) {
              Address [] addrs = node.getAddresses();
              if (addrs.length != 0) {
                s.append(':');
                for (int j = 0; j < addrs.length; j++) {
                  if (j != 0) {
                    s.append('|');
                  }
                  s.append(addrs[j].getCategory()).append('=');
                  s.append(addrs[j].getAddress());
                }
              }
            }
          }
          s.append(')');
        }
        boolean stacktrace = false;
        AdditionalData [] data = event.getAdditionalData();
        if (data != null && data.length != 0) {
          s.append(" AdditionalData(");
          s2.append(" AdditionalData(");
          for (int i = 0; i < data.length; i++) {
            if (i != 0) {
              s.append(',');
              s2.append(',');
            }
            s.append(data[i].getMeaning());
            s2.append(data[i].getMeaning());
            if(data[i].getMeaning().equals("STACK_TRACE")) {
              stacktrace=true;
            }
            s.append(':');
            s2.append(':');
            if (data[i].getAdditionalData() != null) {
              if(stacktrace) {
                StringBuffer stackdata= new StringBuffer(data[i].getAdditionalData());
                int index = stackdata.indexOf(")");
                if(index == -1) {
                  s.append(data[i].getAdditionalData());
                }
                else {
                  s.append(stackdata.substring(0,index));
                  s.append(")");
                }
                // Exception exp=new Exception(stackdata);
                // s.append(exp.getMessage());
              }
              else {
                s.append(data[i].getAdditionalData());
              }
              s2.append(data[i].getAdditionalData());
            } else {
              XMLSerializable xml = data[i].getXMLData();
              if (xml instanceof Agent) {
                Agent agent = (Agent) xml;
                s.append(agent.getName());
                s2.append(agent.getName());
              }
            }
          }
        }
        s.append(')');
        s2.append(')');
        String idmefString = s2.toString();
        long lastPublished = System.currentTimeMillis();
       	Long pTime = (Long)_eventCache.get(idmefString);
        if (pTime != null) {
          if (lastPublished - pTime.longValue() < _cacheInterval) {
            if (_log.isDebugEnabled()) {
              _log.debug("Idmef message already published for " + idmefString + "at time :"+ pTime);
            }
            return;
          }        
        }
        else {
          if (_log.isDebugEnabled()) {
            _log.debug("adding new entry: " + idmefString);
          }
        }

        if (_eventCache.size() > _cacheSize) {
          // lazy clean up, restart the cache over
          if (_log.isDebugEnabled()) {
            _log.debug("Cleaning cache");
          }
          _eventCache.clear();
        } 
        if (_log.isDebugEnabled()) {
            _log.debug("adding Event to cache");
          }
        _eventCache.put(idmefString, new Long(lastPublished)); 
        
        if (_log.isDebugEnabled()) {
            _log.debug("adding Event to cache");
          }
        _eventService.event(s.toString());
      }
    }
  }

}
