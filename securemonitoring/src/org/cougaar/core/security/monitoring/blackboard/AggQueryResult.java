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

public class AggQueryResult implements Publishable, Serializable {

  private UID _uid;
  private int _total;
  private int _currentcount;
  private double _rate;
  
  public AggQueryResult ( UID uid ) {
    _uid=uid;
    _total=0;
    _currentcount=0;
    _rate=0.0;
  }
  public AggQueryResult ( UID uid ,int currentcount, int  total ) {
    _uid=uid;
    _total=total;
    _currentcount=currentcount;
    _rate=0.0;
  } 
  
  public AggQueryResult ( int currentcount, int  total , double rate) {
    _uid=null;
    _total=total;
    _currentcount=currentcount;
    _rate=rate;
  } 
  public AggQueryResult ( UID uid, int currentcount, int  total , double rate) {
    _uid=uid;
    _total=total;
    _currentcount=currentcount;
    _rate=rate;
  } 
  
  public UID getUID() {
    return _uid;
  }
  
  public void setCurrentCount(int currentCount) {
    _currentcount=currentCount;
  }
  
  public void setTotal(int total) {
    _total=total; 
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

  public void resetCurrentCount(){
    _currentcount=0;
  }

  public void incrementCurrentCount() {
    _currentcount++;
    _total++;
  }


  public void setRate(double rate) {
    _rate=rate;
  }

  public double getRate() {
    return _rate;
  }
  public boolean isPersistable() {
    return true;
  }

  public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append("Query id:"+ _uid.toString()+"\n");
    buff.append("Count="+_currentcount+"\n");
    buff.append("Total="+_total+"\n");
    return buff.toString();
  }
  
}
