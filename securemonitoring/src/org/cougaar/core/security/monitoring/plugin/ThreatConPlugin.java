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
import java.util.List;

import org.cougaar.core.adaptivity.OMCRangeList;
import org.cougaar.core.adaptivity.OperatingMode;
import org.cougaar.core.adaptivity.OperatingModeImpl;
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

/**
 * This plugin manages the threatcon.
 */
public class ThreatConPlugin extends ComponentPlugin {
  private LoggingService _log;

  private static final String _omName =
  "org.cougaar.core.security.monitoring.PERCEIVED_THREAT_LEVEL";
  private static final String[] OPERATING_MODE_VALUES = {"LOW", "HIGH"};
  private static final OMCRangeList OMRANGE = new OMCRangeList(OPERATING_MODE_VALUES);

  private final UnaryPredicate _threatConPredicate = 
    new UnaryPredicate() {
      public boolean execute(Object o) {
        if (o instanceof OperatingMode) {
	  OperatingMode om = (OperatingMode) o;
	  if (_omName.equals(om.getName())) {
	    return true;
	  }
	}
	return false;
      }
    };

  public void setParameter(Object o) {
    if (!(o instanceof List)) {
      throw new IllegalArgumentException("Expecting a List parameter " +
                                         "instead of " + 
                                         ( (o == null)
                                           ? "null" 
                                           : o.getClass().getName() ));
    }

    List l = (List) o;
  }

  protected void setupSubscriptions() {
    ServiceBroker sb = getServiceBroker();
    _log = (LoggingService)sb.getService(this, LoggingService.class, null);
    rehydrate();
  }

  public void execute() {
  }

  private void rehydrate() {
    Collection c = getBlackboardService().query(_threatConPredicate);
    if (c.isEmpty()) {
      if (_log.isInfoEnabled()) {
        _log.info("No rehydration. Publish Add operating mode: " + _omName);
      }
      // publishAdd the operating mode.
      OperatingMode om = new OperatingModeImpl(_omName, OMRANGE);
      om.setValue("HIGH");
      getBlackboardService().publishAdd(om);
    }
    else {
      OperatingMode om = (OperatingMode) c.iterator().next();
      if (_log.isInfoEnabled()) {
        _log.info("Rehydrating. " + _omName + "=" + om.getValue());
      }
    }
  }
}
