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

import org.cougaar.core.mts.MessageAddress;

import edu.jhuapl.idmef.IDMEF_Message;

/** Event interface
 *  Monitoring & Response sensors use Event objects to signal
 *  that something happened. Event objects should be published
 *  to the blackboard.
 *  Event objects may be processed locally or may be transferred
 *  to remote entities using EventTransfer objects.
 *  If the sensor knows where to send the Event, it may publish
 *  an EventTransfer directly.
 *  
 */
public interface Event extends CmrObject
{

  /**
   * Retrieve the IDMEF message (alert or heartbeat)
   */
  public IDMEF_Message getEvent();

  /**
   * Get the name of the M&R agent that created the event.
   */
  public MessageAddress getSource();

  public org.w3c.dom.Element getXML(org.w3c.dom.Document document);  

  /**
   * Convenience methods to get a synopsis of the IDMEF message
   */
}
