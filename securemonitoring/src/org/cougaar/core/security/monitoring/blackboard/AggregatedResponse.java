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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class AggregatedResponse implements java.io.Serializable {

  private List results;
  
  public AggregatedResponse (List list) {
    this.results=list;
  }
/*
  This method returns an Iterator on the list of Events.It never returns a NULL.
  If List is Null it creates and emptyList and retrns an Iterator on an emptylist.
 */
  public Iterator getEvents() {
    Iterator iterator=null;
    if(results!=null) {
      iterator=results.iterator();
      return iterator;
    }
    List list=new ArrayList();
    return list.iterator();
  }
  public String toString() {
    Iterator iterator=null;
    StringBuffer buff=new StringBuffer();
    if(results!=null) {
      iterator=results.iterator();
      int counter=1;
      buff.append(" Consolidated Events in AggregatedResponse :");
      while(iterator.hasNext()) {
        buff.append(counter+"\n");
        buff.append(iterator.next().toString()+"\n");
        counter++;
      }
    }
    else {
      buff.append("No Consolidated Events  in AggregatedResponse ");
    }
    return buff.toString();
  }
}
