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
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.ConsolidatedCapabilities;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.IDMEF_Message;

public class AllLoginFailures 
  implements UnaryPredicate, QueryClassificationProvider {
  private static final String[] CLASSIFICATIONS = {
    IdmefClassifications.LOGIN_FAILURE
  };
  /**
   * UnaryPredicate API requires this. Selects the
   * objects that we're interested in on the remote Blackboard.
   */
  public boolean execute(Object obj) {
    if (obj instanceof Event) {
      Event event = (Event) obj;
      IDMEF_Message msg = event.getEvent();
      if (msg instanceof RegistrationAlert ||
          msg instanceof ConsolidatedCapabilities) {
        return false;
      }
      if (msg instanceof Alert) {
        Classification[] c = ((Alert) msg).getClassifications();
        if (c != null) {
          for (int i = 0; i < c.length; i++) {
            if (c[i].getName().equals(IdmefClassifications.LOGIN_FAILURE)) {
              return true;
            } // end of if (c.getName().equals('foo'))
          } // end of for (int i = 0; i < c.length; i++)
        } // end of if (c != null)
      } // end of if (msg instanceof Alert)
    }
    return false;
  }
  
  /**
   * QueryClassificationProvider requires this to get a list of sensors
   * that support LOGIN_FAILUREs.
   */
  public String[] getClassifications() {
    return CLASSIFICATIONS;
  }
}


