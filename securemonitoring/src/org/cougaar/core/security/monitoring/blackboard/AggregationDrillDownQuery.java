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



public class AggregationDrillDownQuery implements DrillDownQuery,java.io.Serializable
{
  //AggregationQuery query ;
  String _query;
  AggregationType _type;
  boolean _wantdetails=false;
  boolean _persistent=true;
  UID originators_uid=null;
  
/*
  public AggregationDrillDownQuery (AggregationQuery iQuery, 
  AggregationType iType, 
  boolean iwantDetails) {
    
  _query=iQuery;
  _type=iType;
  _wantdetails=iwantDetails;
  }
  
  public AggregationDrillDownQuery (AggregationQuery iQuery, 
  AggregationType iType ) {
    
  _query=iQuery;
  _type=iType;
  }
*/
  public AggregationDrillDownQuery (UID originatorUID,String  query, 
                                    AggregationType iType ) {
    originators_uid=originatorUID;
    _query=query;
    _type=iType;
  }
  public AggregationDrillDownQuery (String  query, 
                                    AggregationType iType ) {
    
    _query=query;
    _type=iType;
  }
  public AggregationDrillDownQuery (String  query, 
                                    AggregationType iType,
                                    boolean persistent  ) {
    
    _query=query;
    _type=iType;
    _persistent=persistent;
  }
  /**
   */
  /*
    public AggregationQuery getAggQuery() {
    return _query;
    }
  */

  public String getAggQuery() {
    return _query;
  }
  /**
   */
  public AggregationType getAggregationType() {
    return _type;
  }
  /**
   */
  public boolean wantDetails() {
    return _wantdetails;
  }

  public void setOriginatorsUID(UID originatorUID) {
    originators_uid=originatorUID;
  }
   public UID getOriginatorsUID() {
    return originators_uid;
  }

  public boolean isPersistent() {
    return _persistent;
  }
}
