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
import org.cougaar.core.util.UID;
import org.cougaar.planning.servlet.XMLize;

import edu.jhuapl.idmef.IDMEF_Message;

/** Event implementation
 */
public class EventImpl
  implements NewEvent
{
  protected IDMEF_Message theMessage;
  protected MessageAddress theAgent;
  protected UID myUID;

  public EventImpl(UID aUID)
  {
    setUID(aUID);
  }

  public EventImpl(UID aUID,
		   MessageAddress aSource,
		   IDMEF_Message aMessage)
  {
    setUID(aUID);
    setSource(aSource);
    setEvent(aMessage);
  }

  /** ******************************************************************
   *  Event interface
   */

  private void setEvent(IDMEF_Message aMessage)
  {
    theMessage = aMessage;
  }
  private void setSource(MessageAddress aSource) {
    theAgent = aSource;
  }

  public IDMEF_Message getEvent()
  {
    return theMessage;
  }

  public MessageAddress getSource() {
    return theAgent;
  }


  /** ******************************************************************
   *  UniqueObject interface
   */

  /**
   * setUID - set uid for the object
   *
   * @param uid UID assigned to object
   */
  public void setUID(UID uid) {
    myUID = uid;
  }
  
  /**
   * getUID - get uid for the object
   *
   * @return UID assigned to object
   */
  public UID getUID() { 
    return myUID;
  }

  /** ******************************************************************
   *  Publishable interface
   */

  public boolean isPersistable() {
    return true;
  }

  /** ******************************************************************
   *
   */

  public String toString() {
    String s = null;
    if (theMessage != null) {
      s = theMessage.toString();
    }
    return s;
  }
  
  public String getDocument() {
      return toString();
  }
  
  public org.w3c.dom.Element getXML(org.w3c.dom.Document document) {
     return XMLize.getPlanObjectXML(this, document);
  }
  
}
