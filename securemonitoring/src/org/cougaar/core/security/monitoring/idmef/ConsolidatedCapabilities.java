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

package org.cougaar.core.security.monitoring.idmef;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
/**
 * Registration subclasses Alert, and is used to distinguish
 * the difference been an Alert message and a Registration message
 * avoiding the need to determine the message type via the AdditionalData
 * object.
 */
public class ConsolidatedCapabilities extends Alert implements AgentRegistration {
    
  private  String Type =null;
  private String AgentName=null;
  /**
   * Creates a message for an analyzer to register its capabilities.
   * Can only be create through IdmefMessageFactory
   */
  ConsolidatedCapabilities( Analyzer analyzer,
			    Source []sources,
			    Target []targets,
			    Classification []capabilities,
			    AdditionalData []data,
			    String ident,String type,String agentName ){
    super( analyzer, 
	   null, 
	   null,  // detection time
	   null,  // don't think we need AnalyzerTime
	   sources, // sources
	   targets, // targets
	   capabilities,
	   null,    // assessment 
	   data, 
	   ident );  // ident 
    this.Type=type;
    this.AgentName=agentName;
  }
   
  /*public String toString() {
    StringBuffer buff=new StringBuffer();
    buff.append(" ConsolidatedCapabilities are :\n");
    if(getAnalyzer()!=null)
      buff.append(" Analyzer :"+getAnalyzer().getAnalyzerid());
    if(getClassifications()!=null) {
      Classification classs[]=getClassifications();
      Classification classi=null;
      buff.append(" Classifications are :\n");
      for( int i=0;i<classs.length;i++) {
	classi=classs[i];
	buff.append("Classification Name:"+classi.getName());
      }
    }
     return buff.toString();
  }
  */
 
  public void setType(String type) {
    this.Type=type;
  }
   public String getType() {
    return this.Type;
  }

  public String getAgentName() {
    return this.AgentName;
  } 
  

}
