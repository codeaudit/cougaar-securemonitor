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

import org.cougaar.core.util.UID;
import org.cougaar.core.util.UniqueObject;

import java.io.Serializable;
import java.util.Date;

/**
 * This class is used by RateCalculatorPlugin to store data that
 * it needs to persist.
 */
public class RateCalculatorInfo 
  implements Serializable, UniqueObject {

  public RateCalculatorInfo(int [] messages, long startTime,
                            long lastUpdate, String conditionName,
                            UID uid) {
    this.messages = messages;
    this.startTime = startTime;
    this.lastUpdate = lastUpdate;
    this.conditionName = conditionName;
    _uid = uid;
  }

  public UID getUID() {
    return _uid;
  }

  public void setUID(UID uid) {
    _uid = uid;
  }

  /** Used only for XMLizable */
  public String getStartTime() {
    return (new Date(startTime)).toString();
  }

  /** Used only for XMLizable */
  public String getLastUpdate() {
    return (new Date(lastUpdate)).toString();
  }

  /** Used only for XMLizable */
  public String getConditionName() {
    return conditionName;
  }

  public String toString() {
    return "(" + _uid + ", " + startTime + ", " + lastUpdate + ")";
  }

  /** Used only for XMLizable */
  public int getTotalMessages() {
    int count = 0;
    for (int i = 0; i < messages.length; i++) {
      count += messages[i];
    } // end of for (int i = 0; i < messages.length; i++)
    return count;
  }

  int  messages[];
  long startTime;
  long lastUpdate;
  String conditionName;
  UID _uid;
}

