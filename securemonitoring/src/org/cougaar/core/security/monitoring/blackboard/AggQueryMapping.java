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

import org.cougaar.core.blackboard.Publishable;
import org.cougaar.core.util.UID;

import java.io.Serializable;
import java.util.ArrayList;



public class AggQueryMapping implements Publishable, Serializable {
  private ArrayList queryList;
  private UID parentQuery_uid;
  private UID originator_uid;
  private int _total;
  private int _currentcount;
  private double _rate;
  
  public AggQueryMapping (UID originatorUID, UID parentqueryUID, ArrayList query) {
    this.originator_uid=originatorUID;
    this.parentQuery_uid=parentqueryUID;
    this.queryList=query;
    _total=0;
    _currentcount=0;
    _rate=0.0;
    
  }

  public UID getOriginatorUID() {
    return this.originator_uid;
  }
  
   public UID getParentQueryUID() {
    return this.parentQuery_uid;
  }
  
  public ArrayList getQueryList() {
    return this.queryList;
  }
  
  public void setQueryList(ArrayList querylist) {
    this.queryList=querylist;
  }
  
  
  public void setCurrentCount(int currentCount) {
    _currentcount=currentCount;
  }
  
  public void setTotal(int total) {
    _total=total; 
  }
  
  public void setRate(double rate) {
    _rate=rate; 
  }
  /*
    Gives number of event received in a window period specified in AggregateResponseplugin
  */
  public int getCurrentCount(){
    return _currentcount;
  }

  public int getTotal() {
    return _total;
  }
  
  public  double getRate() {
    return _rate;
  }

  public boolean isPersistable() {
    return true;
  }
  
  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append("Originators id:"+ originator_uid.toString()+"\n");
    buff.append("parent id:"+ parentQuery_uid.toString()+"\n");
    buff.append("child are :\n");
    for(int i=0;i<queryList.size();i++) {
      buff.append(queryList.get(i).toString()+"\n");
    }
    buff.append("Count="+_currentcount+"\n");
    buff.append("Total="+_total+"\n");
    buff.append("Rate="+_rate+"\n");
    return buff.toString();
  }
}
