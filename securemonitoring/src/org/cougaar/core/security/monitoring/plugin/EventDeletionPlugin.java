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

import org.cougaar.core.agent.service.alarm.Alarm;
import org.cougaar.core.blackboard.CollectionSubscription;
import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.service.LoggingService;
import org.cougaar.util.UnaryPredicate;
import org.cougaar.util.log.Logger;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.TreeSet;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.IDMEFTime;

/**
 * Deletes old or excessive IDMEF Alert events from the blackboard.  It only deletes
 * Events that contain Alerts.
 * <table width="100%">
 * <tr><td>Parameter Name</td><td>Type</td><td>Meaning</td></tr>
 * <tr><td>pollInterval</td><td>Long</td><td>The time between sweeps of the BB in seconds.
 *   Determines how often we delete events.</td></tr>
 * <tr><td>maxAge</td><td>Long</td><td>The age of the oldest event that will be left
 * on the BB. The value is a duration in seconds. Actually, events will live between 
 * (maxAge) and (pollInterval + maxAge) </td></tr>
 * <tr><td>maxAlerts</td><td>Long</td><td>The maximum number of alert events that will 
 * be allowed to remain on the BB.  If there are more than (maxAlerts) events, the oldest will be deleted
 * until the total count = (maxAlerts)</td></tr>
 * <tr><td>logFile</td><td>String</td><td>The (optional) name of a file (under org.cougaar.workspace) in 
 * which to write the events as they are deleted.  If unspecified, no file is written.</td></tr>
 * </table>
 * (all integer parameters default to Integer.MAX_VALUE)
 * Example:
 * <pre>
 * [ Plugins ]
 * plugin = org.cougaar.core.security.monitoring.plugin.EventDeletionPlugin(pollInterval=10, maxAge=600, maxAlerts=13, logFile=deletedEvents.txt)
 * </pre>
 * Checks for expired events every 10 seconds.
 * Deletes events that are over 600 seconds old.
 * If there are more than 13 events, deletes the oldest until 13 are left.
 * Writes the XML IDMEF text to {org.cougaar.workspace}/deletedEvents.txt
 *
 * @author wwright@bbn.com
 */
public class EventDeletionPlugin extends ComponentPlugin {

  /** Logging service */
  private LoggingService LOG;

  /** The number of milliseconds between checks for stale alerts */
  protected long    pollInterval = Integer.MAX_VALUE;

  /** The maximum age of alerts (millisecs)*/
  protected long    maxAge = Integer.MAX_VALUE;

  /** The maximum number of alerts */
  protected long    maxAlerts = Integer.MAX_VALUE;
  
  /** A file to write the deleted records unto */
  private File logFile = null;
  
  private Alarm alarm;

  /**
   * Subscription to the deletable events on the local blackboard
   */
  protected CollectionSubscription deletableEvents;

  static class DeletableAlertsPredicate implements UnaryPredicate{
      public boolean execute(Object o) {
          boolean ret = false;
          if (o instanceof Event ) {
              Event e=(Event)o;
              return (e.getEvent() instanceof Alert);
          }
          return ret;
      }
  }
  
  /**
   * used to sort the events by create time
   */
  static class TimeComparator implements Comparator {
      public int compare(Object o1, Object o2) {
          if (o1 == o2) return 0;
          Alert a1 = (Alert)((Event)o1).getEvent();
          Alert a2 = (Alert)((Event)o2).getEvent();
          return a1.getCreateTime().getNtpstamp().compareTo(a2.getCreateTime().getNtpstamp());
      }
  }

  private void readParameters() {
      Iterator params = getParameters().iterator();
      while (params.hasNext()) {
          String param = (String)params.next();
          int equals = param.indexOf('=');
          if (equals == -1)
              throw new IllegalArgumentException("Parameter ["+ param +"] has no '=' sign in it");
          String paramName = param.substring(0, equals);
          String paramValue = param.substring(equals+1).trim();
          try {
          if (paramName.equals("pollInterval"))
              pollInterval = Long.parseLong(paramValue) * 1000; // convert to millis
          else if (paramName.equals("maxAge"))
              maxAge = Long.parseLong(paramValue) * 1000; // convert to millis
          else if (paramName.equals("maxAlerts"))
              maxAlerts = Long.parseLong(paramValue);
          else if (paramName.equals("logFile")) {
              File directory = new File(System.getProperty("org.cougaar.workspace", "."));
              if (!directory.exists())
                  directory.mkdirs();
              logFile = new File(directory, paramValue);
          } else 
              throw new IllegalArgumentException("Parameter ["+paramName+"] is unknown");
          } catch (NumberFormatException nfe) {
              if (LOG.isEnabledFor(Logger.ERROR)) LOG.error("Cannot parse parameter ["+paramName+"]",nfe);
          }
      }
      if (LOG.isEnabledFor(Logger.DEBUG)) {
          LOG.debug("pollInterval = "+pollInterval/1000+" seconds");
          LOG.debug("maxAge       = "+maxAge/1000+" seconds");
          LOG.debug("maxAlerts    = "+maxAlerts);
          LOG.debug("logFile      = "+(logFile == null ? "(none)":logFile.getAbsolutePath()));
      }

  }

  protected void setupSubscriptions() {
    LOG = (LoggingService)
	getServiceBroker().getService(this, LoggingService.class, null);

    // This collection sorts by date
    TreeSet myCollection = new TreeSet(new TimeComparator());
    
    deletableEvents = (CollectionSubscription)
      getBlackboardService().subscribe(new DeletableAlertsPredicate(), myCollection, false);

    readParameters();
    
    alarm = wakeAfterRealTime(pollInterval);
    LOG.debug("INIT: alarm = "+alarm.toString());
  }

  public void execute() {
      if (LOG.isEnabledFor(Logger.DEBUG)) {
        dumpSubscription();
      }
      
      try {
          if (deletableEvents.size() > maxAlerts)
              deleteOldest();
          if (alarm.hasExpired()) {
              checkForExpired();
              alarm = wakeAfterRealTime(pollInterval);
          }
      } catch (Exception bad_thing) {
          if (LOG.isEnabledFor(Logger.DEBUG)) LOG.debug("Caught an exception in execute -- what the...???");
          bad_thing.printStackTrace();
      }
  }
 
  /**
   * Only called if LOSG.isDebugEnabled()
   **/
  private void dumpSubscription() {
      
      LOG.debug("Execute over "+deletableEvents.size()+" alerts. subChanged = "+
            deletableEvents.hasChanged()+" alarmExpired: "+alarm.hasExpired());
      return;
      /* This dumps the contents of the subscription
      Iterator events = deletableEvents.iterator();
      int i = 0;
      while (events.hasNext()) {
          Event e = (Event)events.next();
          Alert a = (Alert)e.getEvent();
          LOG.debug("#"+ (i++) +": "+e.getUID()+" t = "+a.getCreateTime().getidmefDate());
      }
       */
  }

  /**
   * Trim the list of events down to the max allowed by deleting the oldest
   **/
  private void deleteOldest() {
      Event[] events = (Event [])deletableEvents.toArray(new Event[0]);
      int numToDelete = events.length - (int)maxAlerts;
      if (LOG.isEnabledFor(Logger.DEBUG)) 
        LOG.debug("Deleting oldest "+numToDelete+" of "+events.length+" Alerts");
      for (int i=0; i<numToDelete; i++) 
          delete(events[i]);
  }

  /**
   * Check to see if there are any expired events.  If there are, delete them.
   **/
  private void checkForExpired() {
      Date expirationTime = new Date(System.currentTimeMillis() - maxAge);
      String ntpExpTime = IDMEFTime.convertToNTP(expirationTime);
      if (LOG.isEnabledFor(Logger.DEBUG)) 
        LOG.debug("Checking "+deletableEvents.size() +" alerts for expiration: exp time = "+IDMEFTime.convertToIDMEFFormat(expirationTime));

      ArrayList toBeKilled = new ArrayList();
      Iterator events = deletableEvents.iterator();
      while (events.hasNext()) {
          Event e = (Event)events.next();
          Alert a = (Alert)e.getEvent();
          if (ntpExpTime.compareTo(a.getCreateTime().getNtpstamp()) > 0) 
              toBeKilled.add(e);
          else
              break;  // the list is sorted, so all the rest are newer
      }
      events = toBeKilled.iterator();
      while (events.hasNext()) {
          delete((Event)events.next());
      }
  }

  /**
   * publishRemove an event.  Optionally log and/or write it to a file.
   */
  private void delete(Event e) {
      if (LOG.isEnabledFor(Logger.DEBUG)) {
          Alert a = (Alert)e.getEvent();
          LOG.debug("Deleting Event: "+e.getUID()+" with time: "+a.getCreateTime().getidmefDate());
      }
      getBlackboardService().publishRemove(e);
      if (logFile != null) {
          try {
              FileWriter fw = new FileWriter(logFile, true);
              fw.write(e.getEvent().toString());
              fw.close();
              fw = null;
          } catch (IOException ioe) {
              LOG.debug("Error writing deleted events to file", ioe);
          }
      }
  }

  /**
   * Stuff stolen from PluginAdapter to wake me up
   * on a timer.
   */
  private Alarm wakeAfterRealTime(long delayTime) { 
    long absTime = System.currentTimeMillis()+delayTime;
    PluginAlarm pa = new PluginAlarm(absTime);
    getAlarmService().addRealTimeAlarm(pa);
    return pa;
  }
  
  private class PluginAlarm implements Alarm {
    private long expiresAt;
    private boolean expired = false;
    public PluginAlarm (long expirationTime) {
      expiresAt = expirationTime;
    }
    public long getExpirationTime() { return expiresAt; }
    public synchronized void expire() {
      if (!expired) {
        expired = true;
        getBlackboardService().signalClientActivity();
      }
    }
    public boolean hasExpired() { return expired; }
    public synchronized boolean cancel() {
      boolean was = expired;
      expired=true;
      return was;
    }
  }
}
