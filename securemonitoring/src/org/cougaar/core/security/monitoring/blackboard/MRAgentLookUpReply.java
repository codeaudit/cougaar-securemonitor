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

import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.jhuapl.idmef.XMLSerializable;
import edu.jhuapl.idmef.XMLUtils;


public class MRAgentLookUpReply implements XMLSerializable  {

  private  List AgentList=null;

  /**
   * Constructor for MRAgentLookUpReply
   * @param responseAgentList  List of AgentIdentifier
   */
  public MRAgentLookUpReply (List responseAgentList) {
    this.AgentList=responseAgentList;
  }
  
  public List getAgentList() {
    return this.AgentList;
  }
  
  private void setAgentList(List agentlist) {
    this.AgentList=agentlist;
  }
  
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public MRAgentLookUpReply (Node node){
    //get userid nodes here
    NodeList children = node.getChildNodes();
    ArrayList agentListNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals("AgentName")){
	String agentid=XMLUtils.getAssociatedString(finger);
	agentListNodes.add(MessageAddress.getMessageAddress(agentid));
      }
    }
    
  }
  public Node convertToXML(Document parent){

    Element agentLookUpReplyNode = parent.createElement("MRAgentLookUpReply");
    if (AgentList!= null){
      if(!AgentList.isEmpty()) {
	ListIterator iter=AgentList.listIterator();
	MessageAddress agentid=null;
	while(iter.hasNext()) {
	  agentid=(MessageAddress)iter.next();
	  Node agentNameNode = parent.createElement("AgentName");
	  agentNameNode.appendChild(parent.createTextNode(agentid.toString()));
	  agentLookUpReplyNode.appendChild(agentNameNode);
	}
      }
    }
    return agentLookUpReplyNode;
  }
  
  public String toString(){
    StringBuffer buff=new StringBuffer("MRAgentLookUpReply data is :");
    if(!AgentList.isEmpty()) {
      int counter=0;
      ListIterator iter=AgentList.listIterator();
      MessageAddress agentid=null;
      while(iter.hasNext()) {
	agentid=(MessageAddress)iter.next();
	buff.append(" Agent no :"+ counter+" agent Name :"+ agentid.toString()+"\n");
	counter++;
      }
    }
    return buff.toString();
  }
  
}
