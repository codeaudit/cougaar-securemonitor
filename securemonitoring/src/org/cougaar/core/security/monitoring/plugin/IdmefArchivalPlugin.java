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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.NotSerializableException;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;

import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.idmef.AgentRegistration;
import org.cougaar.core.security.monitoring.idmef.Registration;
import org.cougaar.core.security.services.util.SecurityPropertiesService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.IDMEF_Message;


public class IdmefArchivalPlugin extends ComponentPlugin {
  
  private SecurityPropertiesService _secprop;
  private IncrementalSubscription _idmefevents;
  private LoggingService _log;
  private int _cacheSize = 100;
  private LinkedList _cache;
  private String topDir;
  private String agentName;
  private FileWriter output=null;
  
  class BBIdmefEventPredicate implements UnaryPredicate{
    public boolean execute(Object o) {
      if (o instanceof Event) {
        IDMEF_Message msg = ((Event) o).getEvent();
        if (msg instanceof Registration ||
            msg instanceof AgentRegistration) {
          return false;
        }
        return (msg instanceof Alert);
      }
      return false;
    }
  }

  protected void setupSubscriptions() {
    _log = (LoggingService)getBindingSite().getServiceBroker().getService
      (this, LoggingService.class, null);
    if (_log.isDebugEnabled()) {
      _log.debug("IdmefArchivalPlugin setupSubscription()");
    }
    _idmefevents = (IncrementalSubscription)
      getBlackboardService().subscribe(new BBIdmefEventPredicate());
    _cache = new LinkedList();
    _secprop = (SecurityPropertiesService) getBindingSite().getServiceBroker().getService
      (this,SecurityPropertiesService.class, null);
    createTopDirStructure();
    File f= createArchiveFile();
    try {
      if(f!=null){
        output=new FileWriter(f,true);
      }
      else {
        if (_log.isWarnEnabled()) {
          _log.warn("Cannot create Archival file for Agent  "+ agentName);
        }
      }
    }
    catch (IOException ioexception) {
      if (_log.isWarnEnabled()) {
        _log.warn("Cannot create IO Stream for "+ agentName +" : " +ioexception.getMessage() );
      }
    }
  }

  private void createTopDirStructure (){
    if(_secprop!=null) {
      //nodeName =  _secprop.getProperty("org.cougaar.node.name");
      MessageAddress myAddress = getAgentIdentifier();
      agentName= myAddress.toString() ;
      String cougaarws  = _secprop.getProperty(SecurityPropertiesService.COUGAAR_WORKSPACE);
      topDir= cougaarws + File.separatorChar + "security" + File.separatorChar + "IdmefEvent_Archival"  ;
      File archivaldir = new File(topDir);
      if (!archivaldir.exists()) {
        archivaldir.mkdirs();
      }
    }
    else {
      if (_log.isWarnEnabled()) {
        _log.warn("Cannot get SecurityPropertiesService . ");
      }
    }
  }
  protected void execute () {
    Collection eventcollection = _idmefevents.getAddedCollection();
    if(!eventcollection.isEmpty()){
      Iterator eventiterator = eventcollection.iterator();
      while (eventiterator.hasNext()){
        Event event=(Event)eventiterator.next();
        _cache.add(event);
        //getBlackboardService().publishRemove(event);
      }
      if(_cache.size()>_cacheSize){
        try {
          removeAndArchive();
        }
        catch (FileNotFoundException fNotFoundexception){
          if (_log.isWarnEnabled()) {
            _log.warn("Cannot archive Idmef Events. "+fNotFoundexception.getMessage() );
          }
        }
        catch(NotSerializableException serialexception){
           if (_log.isWarnEnabled()) {
             _log.warn("Cannot archive Idmef Events. "+serialexception.getMessage() );
           }
        }
        catch (IOException ioexception) {
          if (_log.isWarnEnabled()) {
             _log.warn("Cannot archive Idmef Events. "+ioexception.getMessage() );
           }
          
        }
      }
    }
  }

  private void removeAndArchive() throws IOException,FileNotFoundException {
    /*File file=createArchiveFile();*/
    int noItems = _cache.size()- _cacheSize;
    Event event=null;
     if (_log.isDebugEnabled()) {
       _log.debug("Archiving IDMEF Events . Total of " + noItems + " Archived" + 
         " current cache size  " +_cache.size() + "Cache upper limit "+ _cacheSize );
     }
     //List archivelist= new ArrayList();
     if(output!=null){
       String eventsAsString=null;
       for (int i=0;i<noItems;i++) {
         event=(Event) _cache.removeFirst();
         eventsAsString =event.getEvent().toString();
        /* if (_log.isDebugEnabled()) {
           _log.debug(" Writing event :"+ eventsAsString);
         }*/
         output.write(eventsAsString,0,eventsAsString.length());
         getBlackboardService().publishRemove(event);
       }
       output.flush();
     }
     else{
       if (_log.isWarnEnabled()) {
         _log.warn("Cannot archive Idmef Events.Output stream is null  for Agent  "+ agentName );
       }
     }
  }

  private File createArchiveFile() {
    Calendar cal= Calendar.getInstance();
    Date date=cal.getTime();
    String filename= topDir + File.separatorChar + agentName;
    File f= new File(filename); 
    return f;
  }
    
      
}
