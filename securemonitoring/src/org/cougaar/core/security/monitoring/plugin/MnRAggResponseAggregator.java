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



//Cougaar core  
import org.cougaar.core.blackboard.IncrementalSubscription;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.blackboard.AggQueryMapping;
import org.cougaar.core.security.monitoring.blackboard.AggQueryResult;
import org.cougaar.core.security.monitoring.blackboard.AggregatedResponse;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.CmrRelay;
import org.cougaar.core.security.monitoring.blackboard.ConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.DrillDownQuery;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.EventImpl;
import org.cougaar.core.security.monitoring.blackboard.RemoteConsolidatedEvent;
import org.cougaar.core.security.monitoring.blackboard.SensorAggregationDrillDownQuery;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.util.DrillDownQueryConstants;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.util.UID;
import org.cougaar.lib.aggagent.query.AggregationResultSet;
import org.cougaar.lib.aggagent.query.ResultSetDataAtom;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.IDMEF_Message;


class RemoteResponsePredicate implements  UnaryPredicate{
  
  MessageAddress myAddress;
  
  public  RemoteResponsePredicate(MessageAddress myaddress) {
    myAddress = myaddress;
  }
  public boolean execute(Object o) {
    boolean ret = false;
    if (o instanceof CmrRelay ) {
      CmrRelay relay = (CmrRelay)o;
      ret = ((relay.getSource().equals(myAddress)) &&
             ((relay.getContent() instanceof DrillDownQuery) &&
              (relay.getResponse() instanceof AggregatedResponse)));
    }
    return ret;
  }
}

class LocalResponsePredicate implements UnaryPredicate {

  public boolean execute(Object o) {
    if( o instanceof SensorAggregationDrillDownQuery){
      return true;
    }
    return false;
  }
  
}
class RemoteConsolidatedPredicate implements UnaryPredicate {
  
  UID parentUID;
  public RemoteConsolidatedPredicate(UID puid) {
    parentUID=puid;
    
  }
  public boolean execute(Object o) {
    RemoteConsolidatedEvent rconsolidated=null; 
    if( o instanceof RemoteConsolidatedEvent){
      rconsolidated=(RemoteConsolidatedEvent)o;
      if(rconsolidated.getParentUID().equals(parentUID)){
        return true;
      }
    }
    return false;
  }
}


public class MnRAggResponseAggregator extends MnRAggQueryBase  {
  
  private IncrementalSubscription localResponse;
  private IncrementalSubscription remoteResponse;
  private DocumentBuilderFactory _parserFactory = 
  DocumentBuilderFactory.newInstance();

  protected synchronized void setupSubscriptions() {
    super.setupSubscriptions();
    localResponse = (IncrementalSubscription)getBlackboardService().subscribe
      (new LocalResponsePredicate());
    remoteResponse=(IncrementalSubscription)getBlackboardService().subscribe
      (new  RemoteResponsePredicate(myAddress));
  }

  protected synchronized void execute () {
    if(localResponse.hasChanged()) {
      Collection col=localResponse.getChangedCollection();
      if(!col.isEmpty()){
        processLocalResponse(col);
      }
      else {
        if( loggingService.isDebugEnabled()) {
          loggingService.debug(" Changed List is empty for local response in MnRAggResponseAggregator");
        }
      }
    }
    if(remoteResponse.hasChanged()) {
      Collection col=remoteResponse.getChangedCollection();
      if(!col.isEmpty()){
        processRemoteResponse(col);
      }
      else {
        if( loggingService.isDebugEnabled()) {
          loggingService.debug(" Changed List is empty for remote response in MnRAggResponseAggregator");
        }
      }
    }
  }

  public void processRemoteResponse(Collection remote){
    CmrRelay relay=null;
    Iterator iter=remote.iterator();
   
    AggregatedResponse aggResponse=null;
    UID relayuid=null;
    //QueryResultAdapter sensorResponse=null;
    BlackboardService bbs = getBlackboardService();
    Collection aggQueryMappingCol=bbs.query(new AggQueryMappingPredicate()); 
    while(iter.hasNext()) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Receive Remote  Response in MnRAggResponseAggregator");
      }
      relay=(CmrRelay)iter.next();
      //remoteResponse=(ConsolidatedEvent)relay.getResponse();
      relayuid=relay.getUID();
      Collection remoteConsolidatedResponseCol=bbs.query(new RemoteConsolidatedPredicate(relayuid)); 
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Remote Consolidated Event size  : "+ remoteConsolidatedResponseCol.size());
      }
      AggQueryMapping aggQueryMapping=findAggQueryMappingFromBB(relayuid,aggQueryMappingCol);
      aggResponse=(AggregatedResponse)relay.getResponse();
      Iterator consolidatedIterator=aggResponse.getEvents();
      ConsolidatedEvent remoteResponse=null;
      while(consolidatedIterator.hasNext()){
        remoteResponse=(ConsolidatedEvent)consolidatedIterator.next();
        if( loggingService.isDebugEnabled()) {
          loggingService.debug(" Consolidated event in AggregatedResponse in MnRAggResponseAggregator"+ remoteResponse.toString());
        }
        synchronized(aggQueryMapping) {
          ArrayList queryList=aggQueryMapping.getQueryList();
          if(queryList==null) {
            loggingService.debug("Found Agg query mapping object but Query list empty ");
            //bbs.publishAdd(event);
            continue;
          }
          removeOldRemoteConsolidatedResponse(remoteConsolidatedResponseCol);
          AggQueryResult queryresult=null;
          IDMEF_Message message=null;
          RemoteConsolidatedEvent remoteConsolidatedEvent=null;
          for(int i=0;i<queryList.size();i++) {
            queryresult=(AggQueryResult)queryList.get(i);
            if(queryresult.getUID().equals(relayuid)) {
              message=remoteResponse.getEvent();
              if( loggingService.isDebugEnabled()) {
                loggingService.debug(" Received Remote response :"+message.toString());
                loggingService.debug(" Query mapping Object before Modification  :"+aggQueryMapping.toString());
              }
              if(message instanceof Alert){
                queryresult.setCurrentCount(getRateData((Alert)message,DrillDownQueryConstants.TOTAL_CURRENT_EVENTS));
                queryresult.setTotal(getRateData((Alert)message,DrillDownQueryConstants.TOTAL_EVENTS));
                queryresult.setRate(getRate((Alert)message));
                queryList.set(i,queryresult);
                remoteConsolidatedEvent=new RemoteConsolidatedEvent(remoteResponse);
                if(loggingService.isDebugEnabled()) {
                  loggingService.debug(" publishing REMOTE Consolidated : "+remoteConsolidatedEvent.toString());
                  if(remoteConsolidatedEvent.getSource()!=null){
                    loggingService.debug(" Source REMOTE Consolidated : "+remoteConsolidatedEvent.getSource().toString()); 
                  }
                  else {
                    loggingService.debug(" Source of REMOTE Consolidated is NULL : ");
                  }
                }
                if(loggingService.isDebugEnabled()) {
                  if(remoteConsolidatedEvent.getEvent() instanceof Alert) {
                    loggingService.debug("Newly created Remote consolidated Events  is INSTANCE of ALERT");
                    loggingService.debug("Source REMOTE Consolidated : "+remoteConsolidatedEvent.getSource().toString()); 
                  }
                  else {
                    loggingService.debug("Newly created Remote consolidated Events  is NOT INSTANCE of ALERT");
                  }
                  
                }
                bbs.publishAdd(remoteConsolidatedEvent);
              }
            }// end of if(queryresult.getUID().equals(relayuid))
          }//end of for
          bbs.publishChange(aggQueryMapping); 
          if( loggingService.isErrorEnabled()) {
            loggingService.error(" Query mapping Object AFTER  Modification  :"+aggQueryMapping.toString());
          }
        }// end of synchronized
      }
           
    }//end of while
    
  }
  
  private void removeOldRemoteConsolidatedResponse(Collection oldConsolidatedResponse){
    if(oldConsolidatedResponse.isEmpty()){
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" No old Remote Consolidated Response available:");
      }
    }
    if( loggingService.isDebugEnabled()) {
      if(oldConsolidatedResponse.size()>1) {
        loggingService.debug("Size of Remote Consolidated Response available should not be more than 1  ******");
      }
      loggingService.debug(" Size of old Remote Consolidated Response available is : " +oldConsolidatedResponse.size());
    }
    Iterator iter=oldConsolidatedResponse.iterator();
    RemoteConsolidatedEvent remoteevent=null;
    BlackboardService bbs = getBlackboardService();
    while(iter.hasNext()) {
      remoteevent=(RemoteConsolidatedEvent)iter.next();
      bbs.publishRemove(remoteevent);
    }
  }
  public void processLocalResponse(Collection local){
    Iterator iter=local.iterator();
    SensorAggregationDrillDownQuery sensorResponse=null;
    //QueryResultAdapter sensorResponse=null;
    while(iter.hasNext()) {
      if( loggingService.isDebugEnabled()) {
        loggingService.debug(" Receive Local Response in MnRAggResponseAggregator");
      }
      sensorResponse=(SensorAggregationDrillDownQuery)iter.next();
      AggregationResultSet results = 
        (AggregationResultSet)sensorResponse.getResultSet();
      if (results.exceptionThrown()) {
        loggingService.error("Exception when executing query: " + results.getExceptionSummary());
        loggingService.debug("XML: " + results.toXml());
      } else {
        if( loggingService.isDebugEnabled()){
          loggingService.debug("UID of the received event is :"+sensorResponse.getUID().toString());
        }
        publishAggResultAsEvent(results,sensorResponse.getUID());
      }
    }
  }

  public void publishAggResultAsEvent (AggregationResultSet results,UID uid) {
    Iterator atoms = results.getAllAtoms();
    BlackboardService bbs = getBlackboardService();
    DocumentBuilder parser;
    try {
      parser = _parserFactory.newDocumentBuilder();
    } catch (ParserConfigurationException e) {
      loggingService.error("Can't parse any events. The parser factory isn't configured properly.");
      if( loggingService.isDebugEnabled()){
        loggingService.debug("Configuration error.", e);
      }
      return;
    }
    Collection aggQueryMappingCol=getBlackboardService().query(new AggQueryMappingPredicate()); 
    AggQueryMapping aggQueryMapping=findAggQueryMappingFromBB(uid,aggQueryMappingCol);
    if( loggingService.isDebugEnabled()) {
      loggingService.debug("Found mapping object for UID :"+ uid +" Query mapping Object "+aggQueryMapping.toString());
      
    }
    int counter=0;
    while (atoms.hasNext()) {
      ResultSetDataAtom d = (ResultSetDataAtom) atoms.next();
      String owner = d.getIdentifier("owner").toString();
      String id = d.getIdentifier("id").toString();
      String source = d.getValue("source").toString();
      String xml = d.getValue("event").toString();
      IDMEF_Message message= IDMEF_Message.createMessage(xml);
      Event event=null;
      if(aggQueryMapping==null) {
        if( loggingService.isDebugEnabled()){
          loggingService.error("Cannot get Agg queryMapping object for UID ."+ uid);
        }
        /*
          event = new EventImpl(new UID(owner,Long.parseLong(id)),
          MessageAddress.getMessageAddress(source),
          IDMEF_Message.createMessage(xml));
          bbs.publishAdd(event);
        */
        continue;
      }
      if(message instanceof Alert) {
        Alert alert=(Alert)message;
        AdditionalData additionalDataArray []=alert.getAdditionalData();
        AdditionalData modifiedadditionalDataArray []=null;
        if(additionalDataArray!=null) {
          modifiedadditionalDataArray=updateAdditionalData(additionalDataArray,aggQueryMapping);
        }
        alert.setAdditionalData(modifiedadditionalDataArray);
        message=alert;
      }
      

      event = new EventImpl(new UID(owner,Long.parseLong(id)),
                            MessageAddress.getMessageAddress(source),
                            message);
      
      
      if( loggingService.isDebugEnabled()){
        loggingService.debug("Going to modify aggQueryMapping  ");
      }
      synchronized(aggQueryMapping) {
        ArrayList queryList=aggQueryMapping.getQueryList();
        if(queryList==null) {
          loggingService.debug("Found Agg query mapping object but Query list empty ");
          bbs.publishAdd(event);
          continue;
        }
        AggQueryResult queryresult=null;
        for(int i=0;i<queryList.size();i++) {
          queryresult=(AggQueryResult)queryList.get(i);
          if(queryresult.getUID().equals(uid)) {
            queryresult.incrementCurrentCount();
            queryList.set(i,queryresult);
          }
        }
      }
      if( loggingService.isDebugEnabled()){
        loggingService.debug("Going to publish modified aggQueryMapping  "+aggQueryMapping.toString());
      }
      bbs.publishChange(aggQueryMapping);
      bbs.publishAdd(event);
      /*
        if( loggingService.isDebugEnabled()){
        loggingService.debug("received event is :"+event.toString());
        }
      */
      counter++;
    }// end of while
    if( loggingService.isDebugEnabled()){
      loggingService.debug("Published total : "+ counter +" for uid :"+ uid);
    }
  }

  public AdditionalData[] updateAdditionalData(AdditionalData[] inAdditionalData,AggQueryMapping queryMapping) {
    AdditionalData[] outAdditionalData=null;
    IdmefMessageFactory imessage=null;
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if(factory==null){
      if( loggingService.isDebugEnabled()){
        loggingService.debug("Unable to add parent UID and Originators UID to Events Additional data as CmrFactory is NULL "
                             +queryMapping.toString());
      }
      return outAdditionalData;
    }
    imessage=factory.getIdmefMessageFactory();
    if(imessage==null) {
      if( loggingService.isDebugEnabled()){
        loggingService.debug("Unable to add parent UID and Originators UID to Events Additional data as IDMEF Message Factory is NULL "
                             +queryMapping.toString());
      } 
    }
    
    //ADDING PARENT UID AS WELL AS ORIGINATORS UID
    outAdditionalData=new AdditionalData[inAdditionalData.length + 2];
    System.arraycopy(inAdditionalData,0,outAdditionalData,0,inAdditionalData.length);
    AdditionalData adddata=null;
    adddata = imessage.createAdditionalData(AdditionalData.STRING,DrillDownQueryConstants.ORIGINATORS_UID, 
                                            queryMapping.getOriginatorUID().toString());
    outAdditionalData[inAdditionalData.length]=adddata;
   
    adddata = imessage.createAdditionalData(AdditionalData.STRING,DrillDownQueryConstants.PARENT_UID, 
                                            queryMapping.getParentQueryUID().toString());
    outAdditionalData[inAdditionalData.length+1]=adddata;
    return outAdditionalData;
    
  }
  
  public int getRateData(Alert alert, String meaning) {
    int currentcount=-1;
    AdditionalData additionalDataArray[]=alert.getAdditionalData();
    if(additionalDataArray==null){
      return currentcount;
    }
    if(additionalDataArray.length==0) {
      return currentcount;
    }
    AdditionalData additionalData=null;
    String count=null;
    for(int i=0;i<additionalDataArray.length;i++) {
      additionalData=additionalDataArray[i];
      if((additionalData.getMeaning().equals(meaning))&&
         (additionalData.getType().equals(AdditionalData.INTEGER))){
        count=additionalData.getAdditionalData();
        try {
          currentcount=Integer.parseInt(count.trim());
        }catch( NumberFormatException nexp) {
          return currentcount;
        }
        return currentcount;
      }
    }
    return currentcount;
  }
  
  public double getRate(Alert alert) {
    double rate=-1.0d;
    AdditionalData additionalDataArray [] =alert.getAdditionalData();
    if(additionalDataArray==null){
      return rate;
    }
    if(additionalDataArray.length==0) {
      return rate;
    }
    AdditionalData additionalData=null;
    String count=null;
    for(int i=0;i<additionalDataArray.length;i++) {
      additionalData=additionalDataArray[i];
      if((additionalData.getMeaning().equals(DrillDownQueryConstants.RATE))&&
         (additionalData.getType().equals(AdditionalData.REAL))){
        count=additionalData.getAdditionalData();
        try {
          rate=Double.parseDouble(count.trim());
        }catch( NumberFormatException nexp) {
          return rate;
        }
        return rate;
      }
    }
    return rate;
  }
  
 
}
