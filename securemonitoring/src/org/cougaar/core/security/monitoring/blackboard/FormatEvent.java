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
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.lib.aggagent.session.IncrementFormat;
import org.cougaar.lib.aggagent.session.SubscriptionAccess;
import org.cougaar.lib.aggagent.session.UpdateDelta;
import org.cougaar.util.ConfigFinder;

import java.util.Collection;
import java.util.Iterator;

import edu.jhuapl.idmef.IDMEF_Message;


public class FormatEvent implements IncrementFormat {
  // IncrementFormat API
  public void encode(UpdateDelta out, SubscriptionAccess sacc) {
    Collection addTo = out.getAddedList();
    Collection added = sacc.getAddedCollection();
    out.setReplacement(true);

    if (added == null) {
      return;
    }

    Iterator iter = added.iterator();
    ConfigFinder cf = ConfigFinder.getInstance();
    IDMEF_Message.setDtdFileLocation(cf.locateFile("idmef-message.dtd").toString());
    while (iter.hasNext()) {
      Event event = (Event) iter.next();
      ResultSetDataAtom da = new ResultSetDataAtom();
      UID uid = event.getUID();
      da.addIdentifier("owner", uid.getOwner());
      da.addIdentifier("id", String.valueOf(uid.getId()));
      da.addValue("source", event.getSource().toAddress());
      da.addValue("event", event.getEvent().toString());
      addTo.add(da);
    }
  }
}
