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

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Calendar;
import java.util.Collection;
import java.util.Iterator;

import edu.jhuapl.idmef.IDMEF_Message;


public class IdmefEventLoggerPlugin extends ComponentPlugin {
  
  private DomainService domainService = null;
  private IncrementalSubscription idmefevents;
  private LoggingService loggingService;
  private MessageAddress myAddress=null;
  private SecurityPropertiesService secprop = null; 
  private PrintStream eventlog=null;
  /**
   * A predicate that matches all "Event object which is not registration "
   */
  class IdemfEventPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      boolean ret = false;
      if (o instanceof Event ) {
	Event e=(Event)o;
	IDMEF_Message msg=e.getEvent();
	if(msg instanceof Registration){
	  return false;
	}
	else if(msg instanceof AgentRegistration) {
	  return false;
	}
	ret=true;      
      }
      return ret;
    }
  }
  
 
  protected void setupSubscriptions() {
    loggingService = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    secprop=(SecurityPropertiesService)getBindingSite().getServiceBroker().getService
      (this, SecurityPropertiesService.class, null);
    myAddress = getAgentIdentifier();
    createEventFile(myAddress.toString());
    loggingService.debug("setupSubscriptions of IDMEF event Logger  called :"
			 + myAddress.toString());
    idmefevents=(IncrementalSubscription)getBlackboardService().subscribe(new IdemfEventPredicate());
  }

  public void createEventFile(String nodeName) {

    // Get name of the log file
    String sep =  System.getProperty("file.separator", "/");
    // Since multiple nodes may run on the same machine, we need
    // to make sure two nodes will not write to the same log file.
    // Also, log files should not be overwritten each time a
    // node is started again (for forensic purposes).
    Calendar rightNow = Calendar.getInstance();
    String curTime = rightNow.get(Calendar.YEAR) + "-" +
      rightNow.get(Calendar.MONTH) + "-" +
      rightNow.get(Calendar.DAY_OF_MONTH) + "-" +
      rightNow.get(Calendar.HOUR_OF_DAY) + "-" +
      rightNow.get(Calendar.MINUTE);

    StringBuffer buffer=new StringBuffer( secprop.getProperty("org.cougaar.workspace", ""));
    buffer.append(sep+"security"+ sep + "IdmefEvents");
    File eventfile=new File(buffer.toString());
    if(!eventfile.exists()) {
      try {
	eventfile.mkdirs();
      }
      catch (Exception e) {
	System.err.println("IDMEF Event log file cannot be created as dir structure does not exist \n" + e.toString());
      }
      buffer.append(sep+"IdmefEvents_"+nodeName+"_" + curTime + ".log");
	
    }
    String logname = System.getProperty("org.cougaar.core.security.IdmefEvents",
					buffer.toString());
    try {
      eventlog = new PrintStream(new FileOutputStream(logname));
     
    }
    catch (IOException e) {
      System.err.println("IDMEF Event log file not opened properly\n" + e.toString());
    }
    
  }
  
  protected void execute () {
    Collection eventcollection=idmefevents.getAddedCollection();
    Iterator eventiterator=eventcollection.iterator();
    Object event=null;
    while(eventiterator.hasNext()) {
      event=(Object)eventiterator.next();
      if(eventlog!=null) {
	eventlog.print(event.toString());
	eventlog.println();
      }
    }
  }
}
