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


package org.cougaar.core.security.monitoring.util;

import org.cougaar.core.util.UID;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.IDMEF_Message;

public class DrillDownUtils {

  public static boolean matchParentUID(IDMEF_Message message,UID givenUID){
    boolean matches =false;
    if(!(message instanceof Alert)){
      // System.out.println(" Returning as IDMEF Message in matchParentUID is NOT INSTANCE of ALERT");
      return matches;
    }
    Alert alert=(Alert)message;
    AdditionalData [] additionalDataArray=alert.getAdditionalData();
    if(additionalDataArray==null || additionalDataArray.length==0) {
      return matches;
    }
    AdditionalData additionalData=null;
    for(int i=0;i<additionalDataArray.length;i++) {
      additionalData=additionalDataArray[i];
      if(additionalData.getMeaning().equals(DrillDownQueryConstants.PARENT_UID)) {
        if(additionalData.getAdditionalData().equals(givenUID.toString())){
          matches=true;
          return matches;
        }
      }
    }
    return matches; 
  }

  public static boolean matchOriginatorUID(IDMEF_Message message,UID givenUID){
    boolean matches =false;
    if(!(message instanceof Alert)){
      System.out.println(" Returning as IDMEF Message in matchOriginatorsUID is NOT INSTANCE of ALERT");
      return matches;
    }
    Alert alert=(Alert)message;
    AdditionalData [] additionalDataArray=alert.getAdditionalData();
    if(additionalDataArray==null || additionalDataArray.length==0) {
      return matches;
    }
    AdditionalData additionalData=null;
    for(int i=0;i<additionalDataArray.length;i++) {
      additionalData=additionalDataArray[i];
      if(additionalData.getMeaning().equals(DrillDownQueryConstants.ORIGINATORS_UID)) {
        if(additionalData.getAdditionalData().equals(givenUID.toString())){
          matches=true;
          return matches;
        }
      }
    }
    return matches; 
  } 

  public static  UID getUID (IDMEF_Message message, String meaning){
    UID uid=null;
    if(!(message instanceof Alert)){
      return uid;
    }
    Alert alert=(Alert)message;
    AdditionalData [] additionalDataArray=alert.getAdditionalData();
    if(additionalDataArray==null || additionalDataArray.length==0) {
      return uid;
    }
    AdditionalData additionalData=null;
    String stringid=null;
    boolean found=false;
    for(int i=0;((i<additionalDataArray.length)&&(!found));i++) {
      additionalData=additionalDataArray[i];
      if(additionalData.getMeaning().equals(meaning)) {
        stringid=additionalData.getAdditionalData();
        found=true;
      }
    }
    if(stringid==null) {
      return uid;
    }
    uid=UID.toUID(stringid);
    return uid;
    
    
  }

  
}
