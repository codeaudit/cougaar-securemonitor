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
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.monitoring.util.DrillDownQueryConstants;
import org.cougaar.core.service.BlackboardService;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;
import org.cougaar.core.util.UID;
import org.cougaar.util.UnaryPredicate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.DetectTime;



public class MnRAggRateCalculator
  implements Runnable, AggregationType,java.io.Serializable
{
  UID _parentUID;
  public long _timewindow;
  private LoggingService _loggingService;
  private DomainService _domainService;
  private BlackboardService _bbs;
  private MessageAddress _self;
  private SensorInfo _sensorinfo;
  final String _name="Event Rate";
  String key="rate_window";
  final int millSecToSec=1000;

  public MnRAggRateCalculator(int timewindow) {
    _timewindow=(long)timewindow*millSecToSec;
    
  }
  public MnRAggRateCalculator(MnRAggRateCalculator ratecalculator) {
    _timewindow=ratecalculator._timewindow;
         
  }
 
  public MnRAggRateCalculator(UID parentUID, int timewindow,MessageAddress self,
                              BlackboardService bbs,LoggingService loggingService,
                              DomainService domainService, SensorInfo sensorinfo){
    _parentUID=parentUID;
    _timewindow=timewindow;
    _loggingService=loggingService;
    _bbs=bbs;
    _domainService=domainService;
    _sensorinfo=sensorinfo;
  }
  public String getName(){
    return _name;
  }
  
  public Map getParameters() {
    Map map=new HashMap();
    map.put(key,new Long(_timewindow));
    return map;
  }

  public void setBlackboardService(BlackboardService bbs) {
    _bbs=bbs;
    
  }
  public void setLoggingService(LoggingService loggingService) {
    _loggingService=loggingService;
  }

  public void setUID(UID uid) {
    _parentUID=uid;
  }
  public void setDomainService(DomainService domainService) {
    _domainService=domainService;

  }
  public void setAddress(MessageAddress self) {
    _self=self;
  }
  public void setAnalyzer(SensorInfo sensorinfo) {
    _sensorinfo=sensorinfo;
  } 
  
  public void run() {
    if( _loggingService.isDebugEnabled()) {
      _loggingService.debug(" MnRAggRateCalculator is running for parent id ---------- :"+ _parentUID.toString());
      _loggingService.debug("Start time is :"+new Date(System.currentTimeMillis()).toString());
    }
    Collection aggCol=null;
    _bbs.openTransaction();
    aggCol=  _bbs.query( new UnaryPredicate() {
        public boolean execute(Object o) {
          if (o instanceof AggQueryMapping ) {
            AggQueryMapping aggQuerymapping = (AggQueryMapping )o;
            return (aggQuerymapping.getParentQueryUID().equals(_parentUID));
          }
          return false;
        }
      });
    _bbs.closeTransaction();
    AggQueryMapping aggQuerymappingObject=null;
    if(!aggCol.isEmpty()){
      aggQuerymappingObject=(AggQueryMapping)aggCol.iterator().next();
    }
    
    if(  aggQuerymappingObject==null) {
      if( _loggingService.isDebugEnabled()) {
        _loggingService.debug(" ERROR in GETTING aggQuerymappingObject ");
      }
    }
    CmrFactory factory=null;
    if(_domainService!=null) {
      factory=(CmrFactory)_domainService.getFactory("cmr");
    } 
    if( _loggingService.isDebugEnabled()) {
      _loggingService.debug("Query mapping object before modification in MnRRate publisher is :"+aggQuerymappingObject.toString());
    }
    synchronized (aggQuerymappingObject){
      ArrayList queryList=null;
      queryList= aggQuerymappingObject.getQueryList();
      int _parentCurrentCount=0;
      int _parentTotal=0;
      double _parentRate=0.0;
      if(queryList!=null) {
        AggQueryResult result=null;
        for(int i=0;i<queryList.size();i++) {
          result=(AggQueryResult)queryList.get(i);
          _parentCurrentCount=_parentCurrentCount+result.getCurrentCount();
          _parentTotal= _parentTotal+result.getTotal();
          result.resetCurrentCount();
          queryList.set(i,result);
        }// end of for
        aggQuerymappingObject.setCurrentCount(_parentCurrentCount);
        aggQuerymappingObject.setTotal(_parentTotal);
        _parentRate=(double)_parentCurrentCount/(double)_timewindow;
        if( _loggingService.isDebugEnabled()) {
          _loggingService.debug(" Publishing rate for parent id :"+ _parentUID.toString() +_parentRate);
        }
        aggQuerymappingObject.setRate(_parentRate);
      }// end of if
      _bbs.openTransaction();
      _bbs.publishChange(aggQuerymappingObject);
      if( _loggingService.isDebugEnabled()) {
        _loggingService.debug(" Publishing Modified Query Mapping object in MnR Rate publisher  :"+aggQuerymappingObject.toString());
      }
      Alert alert=createConsolidatedAlert(factory,aggQuerymappingObject.getOriginatorUID(),
                                          aggQuerymappingObject.getParentQueryUID(),
                                          _parentCurrentCount,_parentTotal,_parentRate);
      ConsolidatedEvent event=factory.newConsolidatedEvent(_self,alert);
      if( _loggingService.isDebugEnabled()) {
        _loggingService.debug(" Created Consolidated event with source:"+ event.getSource() + " agent is  : "+ _self);
      }
      _bbs.publishAdd(event);
      // _bbs.publishAdd(new AggQueryResult(aggQuerymappingObject.getRelayUID(),_parentCurrentCount,_parentTotal,_parentRate));
      _bbs.closeTransaction();
    }// end of synchronized 
    if( _loggingService.isDebugEnabled()) {
      _loggingService.debug(" Publishing new QueryMapping obj for parent id :"+ _parentUID.toString()+
                            "Query Mapping object :"+aggQuerymappingObject.toString());
         
      _loggingService.debug(" MnRAggRateCalculator is Done  for parent id ----------:"+ _parentUID.toString());
    }
       
  }
  public  Alert createConsolidatedAlert(CmrFactory factory, UID originatorUID, UID parentUID,
                                        int currentcount, int  total , double rate ) {
    IdmefMessageFactory imessage=null;
    Alert alert=null;
    if(factory!=null) {
      imessage=factory.getIdmefMessageFactory();
    }
    if(imessage==null) {
      if( _loggingService.isDebugEnabled()) {
        _loggingService.error(" error cannot get Idmef message factory :"+ _self.toString());
      }
      return alert;
    }
    ArrayList classifications = new ArrayList(1);
    ArrayList targets = new ArrayList(1);
    ArrayList sources=new ArrayList(1);
    DetectTime detecttime=new DetectTime();
    ArrayList data = new ArrayList();
    AdditionalData adddata=null;
    boolean consolidated=true;
    adddata = imessage.createAdditionalData(AdditionalData.BOOLEAN,
                                            DrillDownQueryConstants.CONSOLIDATED_EVENTS,
                                            new Boolean(consolidated).toString());
    data.add(adddata);
    adddata = imessage.createAdditionalData(AdditionalData.STRING,
                                            DrillDownQueryConstants.ORIGINATORS_UID, 
                                            originatorUID.toString());
    data.add(adddata);
    adddata = imessage.createAdditionalData(AdditionalData.STRING,
                                            DrillDownQueryConstants.PARENT_UID, 
                                            parentUID.toString());
    data.add(adddata);
    adddata=imessage.createAdditionalData(AdditionalData.INTEGER, 
                                          DrillDownQueryConstants.TOTAL_CURRENT_EVENTS,
                                          new Integer(currentcount).toString() );
    data.add(adddata);
    adddata=imessage.createAdditionalData(AdditionalData.INTEGER, 
                                          DrillDownQueryConstants.TOTAL_EVENTS,
                                          new Integer (total).toString() );
    data.add(adddata);
    adddata=imessage.createAdditionalData(AdditionalData.REAL, 
                                          DrillDownQueryConstants.RATE,
                                          new Double(rate).toString());
    data.add(adddata);
    alert = imessage.createAlert(_sensorinfo, detecttime,
                                 sources, targets,
                                 classifications, data);
    
    return alert;
    
  } 
    
}
