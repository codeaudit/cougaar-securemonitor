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

import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.asset.Asset;

/** EventTransferImpl
 */
public class EventTransferImpl
  extends EventImpl
  implements NewEventTransfer
{
  private Asset targetAsset;

  public EventTransferImpl(UID aUID)
  {
    super(aUID);
  }

  /** 
   * @param aEvent  The event being transferred
   * @param to  The agent that will receive this event for use
   * @param from  The agent that is provided this event for use
   */
  public EventTransferImpl(UID aUID,
			   Asset aTarget,
			   Event aEvent)
  {
    super(aUID, aEvent.getSource(), aEvent.getEvent());
    setTarget(aTarget);
  }

  /** ******************************************************************
   *  EventTransfer interface
   */

  public Asset getTarget()
  {
    return targetAsset;
  }
 
  public void setTarget(Asset toAsset) {
    targetAsset = toAsset;
  }

  /** ******************************************************************
   *
   */

  public String toString() {
    String s = "";
    if (getSource() != null) {
      s = s + getSource().toString() + "->";
    }
    if (getTarget() != null) {
      s = s + getTarget().toString() + "/";
    }
    if (getEvent() != null) {
      s = s + getEvent().toString();
    }
    return s;
  }

}





