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
import org.cougaar.core.security.monitoring.util.DrillDownQueryConstants;
import org.cougaar.core.security.monitoring.util.DrillDownUtils;
import org.cougaar.core.util.UID;
import org.cougaar.planning.servlet.XMLize;

import edu.jhuapl.idmef.IDMEF_Message;

/** Event implementation
 */
public class ConsolidatedEventImpl extends ConsolidatedEventBase implements ConsolidatedEvent
{
  public ConsolidatedEventImpl(MessageAddress aSource,
                               IDMEF_Message aMessage)  {
    super(aSource,aMessage);
  }

  
  public String toString() {
    StringBuffer buff=new StringBuffer("Consolidated Event : \n");
    if(theAgent!=null){
      buff.append(" Source :"+ theAgent+"\n");
    }
    String s = null;
    if (theMessage != null) {
      s = theMessage.toString();
      buff.append("Message : "+ s+ "\n");
    }
    return buff.toString();
  }
  
  
  
}
