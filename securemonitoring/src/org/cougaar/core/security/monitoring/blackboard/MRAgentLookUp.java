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


import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.XMLSerializable;
import edu.jhuapl.idmef.XMLUtils;

public class MRAgentLookUp
  implements XMLSerializable
{

  /** If set, the lookup returns sensors that are in the specified community. */
  public String community;

  /** If set, the lookup returns sensors that are in the specified role. */
  public String role;

  /** If set, the lookup returns sensors that monitor the specified source. */
  public Source source;

  /** If set, the lookup returns sensors that monitor the specified target. */
  public Target target;

  /** If set, the lookup returns sensors that monitor the specified classification. */
  public Classification classification;

  /** If set, the lookup returns sensors that monitor the specified source agent. */
  public String source_agent;

  /** If set, the lookup returns sensors that monitor the specified target agent. */
  public String target_agent;

  /** Will get reply updates if set to true. */
  public boolean updates;

  public MRAgentLookUp (String findcommunity,
			String findrole,
			Source findsource,
			Target findtarget,
			Classification findclassification,String sourceagent,String targetagent,boolean updates) {
    this.community=findcommunity;
    this.role=findrole;
    this.source=findsource;
    this.target=findtarget;
    this.classification=findclassification;
    this.source_agent=sourceagent;
    this.target_agent=targetagent;
    this.updates=updates;
  }
  
  public MRAgentLookUp (String findcommunity,
			String findrole,
			Source findsource,
			Target findtarget,
			Classification findclassification,String sourceagent,String targetagent) {
    this.community=findcommunity;
    this.role=findrole;
    this.source=findsource;
    this.target=findtarget;
    this.classification=findclassification;
    this.source_agent=sourceagent;
    this.target_agent=targetagent;
    this.updates=false;
  }
  
   /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public MRAgentLookUp (Node inNode){

    Node communityNode =  XMLUtils.GetNodeForName(inNode, "Community");
    if (communityNode == null) community = null;
    else community = XMLUtils.getAssociatedString(communityNode);

    Node roleNode =  XMLUtils.GetNodeForName(inNode, "Role");
    if (roleNode == null) role = null;
    else role = XMLUtils.getAssociatedString(roleNode); 

    Node sourceNode =  XMLUtils.GetNodeForName(inNode, "Source");
    if (sourceNode == null) source = null;
    else source = new Source (sourceNode);

    Node targetNode =  XMLUtils.GetNodeForName(inNode, "Target");
    if (targetNode == null) target = null;
    else target = new Target (targetNode);
    
    Node classificationNode =  XMLUtils.GetNodeForName(inNode, "Classification");
    if (classificationNode == null) classification = null;
    else classification  = new Classification (classificationNode);
    
    Node sourceAgentNode =  XMLUtils.GetNodeForName(inNode, "SourceAgentName");
    if (sourceAgentNode == null) source_agent = null;
    else source_agent  = XMLUtils.getAssociatedString(sourceAgentNode);

    Node targetAgentNode =  XMLUtils.GetNodeForName(inNode, "TargetAgentNode");
    if (targetAgentNode == null) target_agent= null;
    else target_agent  = XMLUtils.getAssociatedString(targetAgentNode);
    
    Node updateNode =  XMLUtils.GetNodeForName(inNode, "Updates");
    if (updateNode == null) updates = false;
    else updates  = new Boolean ( XMLUtils.getAssociatedString(updateNode)).booleanValue();
        
  }

  public Node convertToXML(Document parent){
    Element agentLookUpNode = parent.createElement("MRAgentLookUp");
    if(community!=null) {
       Node communityNode = parent.createElement("Community");
       communityNode.appendChild(parent.createTextNode(community));
       agentLookUpNode.appendChild(communityNode);
    }
    if(role!=null) {
       Node roleNode = parent.createElement("Role");
       roleNode.appendChild(parent.createTextNode(role));
       agentLookUpNode.appendChild(roleNode);
    }
    if(source != null){
      Node sourceNode = source.convertToXML(parent);
      agentLookUpNode.appendChild(sourceNode);
	    
    }
    if(target != null){
      Node targetNode = target.convertToXML(parent);
      agentLookUpNode.appendChild(targetNode);
      
    }
    if(classification != null){
      Node classificationNode = classification.convertToXML(parent);
      agentLookUpNode.appendChild(classificationNode);
      
    }
    
    if(source_agent!=null) {
      Node sourceAgentNode = parent.createElement("SourceAgentName");
      sourceAgentNode.appendChild(parent.createTextNode(source_agent));
      agentLookUpNode.appendChild(sourceAgentNode);
    }
    if(target_agent!=null) {
      Node targetAgentNode = parent.createElement("TargetAgentName");
      targetAgentNode.appendChild(parent.createTextNode(target_agent));
      agentLookUpNode.appendChild(targetAgentNode);
    }
    if(updates) {
      Node updateNode = parent.createElement("Updates");
      updateNode.appendChild(parent.createTextNode("true"));
      agentLookUpNode.appendChild(updateNode);
    }
    
    return agentLookUpNode;
  
  }

  public String getCommunity() {
    return community;
  }

  public String getRole() {
    return role;
  }
  public Source getSource() {
    return source;
  }
  public Target getTarget() {
    return target;
  }
  public Classification getClassification() {
    return classification;
  }
  public String getSourceAgent() {
    return source_agent;
  }
  public String getTargetAgent() {
    return target_agent;
  }
  public boolean getIsUpdatable() {
    return updates;
  }

  public String toString() {
    StringBuffer buff=new StringBuffer(" MRAgent Look up Object :\n");
    if(community!=null) {
      buff.append(" Destination Community : "+community +"\n");
    }
    if(role!=null) {
      buff.append(" Destination Role : "+role+"\n" );
    }
    if(source!=null) {
      buff.append(" Destination Source : "+ source+"\n" );
    }
    if(target!=null) {
      buff.append(" Destination Target: "+target +"\n");
    }
    if(classification!=null) {
      buff.append(" Destination Classification : "+ classification.getName() +"\n" );
    }
    if(source_agent!=null) {
       buff.append("Source Agent Name  : "+ source_agent +"\n" );
    }
    if(target_agent!=null) {
       buff.append("Target Agent Name  : "+ target_agent +"\n" );
    }
    buff.append(" Updates :"+updates +"\n" );
    return buff.toString();
  }
}
