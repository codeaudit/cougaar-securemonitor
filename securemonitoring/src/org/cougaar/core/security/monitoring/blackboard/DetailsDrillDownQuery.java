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

import org.cougaar.core.util.UID;

public class DetailsDrillDownQuery implements java.io.Serializable {

  private UID originator_UID=null;
  private UID parentQuery_UID=null;
  
  public DetailsDrillDownQuery(UID originatorID, UID parentQueryID) {
    originator_UID=originatorID;
    parentQuery_UID=parentQueryID;
    
  }

  public UID getOriginatorUID(){
    return originator_UID;
  }
  public UID getParentUID(){
    return parentQuery_UID;
  }

  public String toString() {
    StringBuffer buff=new StringBuffer(" DetailsDrillDownQuery: \n");
    if(originator_UID==null) {
      buff.append("Originator UID : NULL \n");
    }
    else {
      buff.append("Originator UID :"+originator_UID + "\n");
    }
    if(parentQuery_UID ==null) {
      buff.append("Parent UID : NULL \n");
    }
    else {
      buff.append("Parent  UID :"+parentQuery_UID + "\n");
    }
    return buff.toString();
      
  }
} 
