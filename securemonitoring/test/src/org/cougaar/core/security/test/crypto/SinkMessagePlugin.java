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

package org.cougaar.core.security.test.crypto;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Hashtable;
import java.util.List;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.service.ThreadService;
import org.cougaar.core.thread.Schedulable;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

public class SinkMessagePlugin extends ComponentPlugin {
  /**
   * for set/get DomainService
   */
  protected DomainService  _domainService;

  private ByteArrayOutputStream _bos;
  private ObjectOutputStream _oos;

  private LoggingService  _log;
  private ThreadService   _threadService;
  private Hashtable       _sent = new Hashtable();
  private UnaryPredicate  _pred = new UnaryPredicate() {
      public boolean execute(Object obj) {
        return (obj instanceof CmrRelay &&
                ((CmrRelay) obj).getContent() instanceof UID);
      }
    };
  private IncrementalSubscription _subscription;
  private MessageAddress _destination;
  private Schedulable _pingThread;

  private int        _sendCount = 10;
  /** Time to wait before sending messages
   */
  private int        _initialDelay = 10 * 1000;

  /** Delay in ms between every message
   */
  private int        _sendDelay = 10;
  /** Size of messages (in bytes)
   */
  private int        _msgSize = 1000;
  private boolean    _sendMsg = false;
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

  public void setThreadService(ThreadService aThreadService) {
    _threadService = aThreadService;
  }
  public ThreadService getThreadService() {
    return _threadService;
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
      _destination =  MessageAddress.getMessageAddress(arr[0].toString());
      System.out.println("_destination = " + _destination);
    }
    if (arr.length > 1) {
      _sendCount = Integer.parseInt(arr[2].toString());
      System.out.println("_sendCount = " + _sendCount);
    } // end of else
    if (arr.length > 2) {
      _initialDelay = Integer.parseInt(arr[2].toString());
      System.out.println("_initialDelay = " + _initialDelay);
    } // end of else
    if (arr.length > 3) {
      _sendDelay = Integer.parseInt(arr[3].toString());
      System.out.println("_sendDelay = " + _sendDelay);
    } // end of else
    if (arr.length > 4) {
      _msgSize = Integer.parseInt(arr[4].toString());
      System.out.println("_msgSize = " + _msgSize);
    } // end of else
    if (arr.length > 5) {
      _sendMsg = Boolean.getBoolean(arr[5].toString());
      System.out.println("_sendMsg = " + _sendMsg);
    } // end of else
  }

  protected void execute() {
  }

  /**
   * Sets up the AggregationQuery and event subscriptions.
   */
  protected void setupSubscriptions() {
    _log = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    _pingThread = getThreadService().getThread(this, new PingThread());
    _pingThread.scheduleAtFixedRate(0, _sendDelay);

    _bos = new ByteArrayOutputStream();
    try {
      _oos = new ObjectOutputStream(_bos);
    }
    catch (Exception e) {
      _log.warn("Unable to create ObjectOutputStream", e);
    }
   
  }


  public long getObjectSize(Object o) {
    _bos.reset();
    try {
      _oos.writeObject(o);
    }
    catch (java.io.IOException ex) {
      _log.warn("Unable to write object to stream", ex);
    }
    return _bos.size();
  }

  private class PingThread
    implements Runnable
  {
    private int _sentMessages;
    private CmrFactory _cmrFactory;
    private static final String _id = "PING_THREAD";

    public PingThread() {
      DomainService ds = getDomainService(); 
      _cmrFactory = (CmrFactory) ds.getFactory("cmr");
      if (_cmrFactory == null) {
	throw new RuntimeException("Unable to get Relay factory");
      }
    }

    public void run() {

      UID uid = new UID(_id, _sentMessages);
      CmrRelay relay = _cmrFactory.newCmrRelay(uid, _destination);
      long size = getObjectSize(relay);
      if (size < _msgSize) {
	// Augment size of object
	byte[] array = new byte[_msgSize - (int)size];
	relay.updateContent(array, null);
	size = getObjectSize(relay);
      }

      if (_log.isDebugEnabled()) {
	_log.debug("Sending relay" + relay
	  + " - Msg number: " + _sentMessages
	  + " - Msg size: " + size);
      }
      BlackboardService bbs = getBlackboardService();
      bbs.openTransaction();
      bbs.publishAdd(relay);
      bbs.closeTransaction();
      _sentMessages++;
      if (_sendCount != -1 && _sentMessages > _sendCount) {
	_pingThread.cancel();
      }

    }
  }
}
