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

package org.cougaar.core.security.test;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

public class BouncePlugin extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;


  private LoggingService  _log;
  private Hashtable       _sent = new Hashtable();
  private UnaryPredicate  _pred = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof CmrRelay &&
                ((CmrRelay) obj).getContent() instanceof UID);
      }
    };
  private IncrementalSubscription _subscription;
  private MessageAddress _destination;

  private CmrFactory _cmrFactory;
  private String     _id;
  private int        _sendCount = 10;

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

  public void setParameter(Object o) {
    System.out.println("setParameter called with: " + o);
    //    Thread.dumpStack();
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
    Object[] arr = l.toArray();
    System.out.println("argument array = " + arr + " with length " + arr.length);

    if (arr.length != 0) {
      _id = arr[0].toString();
    }
    if (arr.length > 1) {
      _destination =  MessageAddress.getMessageAddress(arr[1].toString());
      System.out.println("_destination = " + _destination);
    }
    if (arr.length > 2) {
      _sendCount = Integer.parseInt(arr[2].toString());
      System.out.println("_sendCount = " + _sendCount);
    } // end of else
  }

  protected void execute() {
    if (_subscription.hasChanged()) {
      Enumeration added = _subscription.getAddedList();
      BlackboardService bbs = getBlackboardService();
      while (added.hasMoreElements()) {
        CmrRelay cmr = (CmrRelay) added.nextElement();
        if (_log.isDebugEnabled()) {
          _log.debug("Received " + cmr);
        }
        UID contents = (UID) cmr.getContent();
        CmrRelay sentCmr = (CmrRelay) _sent.get(contents);
        if (sentCmr != null) {
          _sent.remove(contents);
          bbs.publishRemove(sentCmr);
        } else if (_sent.get(cmr.getUID()) != null) {
          continue;
        } // end of if (_sent.get(cmr.getUID()) == null)
        
        bbs.publishRemove(cmr);
        Object o = cmr.getUID();

	MessageAddress ci = null;
	if (_destination != null) {
	  ci = _destination;
	}
	else {
	  ci = cmr.getSource();
	}
	CmrRelay relay = (CmrRelay) _cmrFactory.newCmrRelay(o, ci);
        _sent.put(relay.getUID(), relay);
        if (_log.isDebugEnabled()) {
          _log.debug("sending " + relay);
        }
        bbs.publishAdd(relay);
      } // end of while (added.hasMoreElements())
    } // end of if (_subscription.hasChanged())
    
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    BlackboardService bbs = getBlackboardService();

    _subscription = (IncrementalSubscription) bbs.subscribe(_pred);

    DomainService        ds           = getDomainService(); 
    _cmrFactory                        = (CmrFactory) ds.getFactory("cmr");

    if (_id != null && _destination != null) {
      for (int i = 0; i < _sendCount; i++) {
	UID uid = new UID(_id, i);
	CmrRelay relay = _cmrFactory.newCmrRelay(uid, _destination);
	_sent.put(relay.getUID(), relay);
        if (_log.isDebugEnabled()) {
          _log.debug("Sending initial relay" + relay);
        }
	bbs.publishAdd(relay);
      } // end of for (int i = 0; i < _sent.length; i++)
    }
  }

}
