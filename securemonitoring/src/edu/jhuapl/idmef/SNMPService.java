/* The following passage applies to all software and text files in this distribution, 
including this one:

Copyright (c) 2001, Submarine Technology Department, The Johns Hopkins University 
Applied Physics Laboratory.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    -> Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.

    -> Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

    -> Neither the name of the Johns Hopkins University Applied Physics Laboratory
       nor the names of its contributors may be used to endorse or promote products 
       derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*/

package edu.jhuapl.idmef;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
/** 
 * <pre>
 *  The SNMPService class carries additional information related to SNMP
 *  traffic.
 *
 *  The SNMPService class is composed of three aggregate classes, as
 *  shown in Figure 4.20.
 *
 *               +-------------+
 *               |   Service   |
 *               +-------------+
 *                     /_\
 *                      |
 *               +-------------+
 *               | SNMPService |
 *               +-------------+       0..1 +-----------+
 *               |             |<>----------|    oid    |
 *               |             |            +-----------+
 *               |             |       0..1 +-----------+
 *               |             |<>----------| community |
 *               |             |            +-----------+
 *               |             |       0..1 +-----------+
 *               |             |<>----------|  command  |
 *               |             |            +-----------+
 *               +-------------+
 *
 *                  Figure 4.20 - The SNMPService Class
 *
 *  The aggregate classes that make up SNMPService are:
 *
 *  oid
 *     Zero or one.  STRING.  The object identifier in the request.
 *
 *  community
 *     Zero or one.  STRING.  The object's community string.
 *
 *  command
 *     Zero or one.  STRING.  The command sent to the SNMP server (GET,
 *     SET.  etc.).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT SNMPService                   (
 *         oid?, community?, command?
 *     )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class SNMPService extends Service implements XMLSerializable{

    private static final String CHILD_ELEMENT_OID = "oid";
    private static final String CHILD_ELEMENT_COMMUNITY = "community";
    private static final String CHILD_ELEMENT_COMMAND = "command";
    
    protected String oid;
    protected String community;
    protected String command;

    public static final String ELEMENT_NAME = "SNMPService";
    
    //getters and setters 
    public String getOid(){
	    return oid;
    }
    public void setOid(String inOid){
	    oid = inOid;
    }


    public String getcommunity(){
	    return community;
    }
    public void setCommunity(String inCommunity){
	    community = inCommunity;
    }

    public String getcommand(){
	    return command;
    }
    public void setCommand(String inCommand){
	    command = inCommand;
    }
    /**Copies arguments into corresponding fields.
      */
    public SNMPService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      String inOid, String inCommunity, String inCommand){
	
	    super(inName, inPort, inPortlist, inProtocol, inIdent);

	    oid = inOid;
	    community = inCommunity;
	    command = inCommand;
    }
    /**
     * Creates an object with all fields null.
     */
    public SNMPService(){
	    this(null, null, null, null, null, null, null, null);
    }
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public SNMPService (Node node){
	    super(node);
      Node oidNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_OID);
    	if (oidNode == null) oid = null;
    	else oid = XMLUtils.getAssociatedString(oidNode);
    
    	Node communityNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_COMMUNITY);
    	if (communityNode == null) community = null;
    	else community = XMLUtils.getAssociatedString(communityNode);
    
    	Node commandNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_COMMAND);
    	if (commandNode == null) command = null;
    	else command = XMLUtils.getAssociatedString(commandNode);
    }

    public Node convertToXML(Document parent){
    	Element snmpserviceNode = parent.createElement(ELEMENT_NAME);
    	if(ident != null)
    	    snmpserviceNode.setAttribute(ATTRIBUTE_IDENT, ident);
        	
    	if(name != null){
    	    Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
    	    nameNode.appendChild(parent.createTextNode(name));
    	    snmpserviceNode.appendChild(nameNode);	    
    	}
    	if(port != null){
    	    Node portNode = parent.createElement(CHILD_ELEMENT_PORT);
    	    portNode.appendChild(parent.createTextNode(port.toString()));
    	    snmpserviceNode.appendChild(portNode);
    	}
    	if(portlist != null){
    	    Node portlistNode = parent.createElement(CHILD_ELEMENT_PORTLIST);
    	    portlistNode.appendChild(parent.createTextNode(portlist));
    	    snmpserviceNode.appendChild(portlistNode);
    	}
    	if(protocol != null){
    	    Node protocolNode = parent.createElement(CHILD_ELEMENT_PROTOCOL);
    	    protocolNode.appendChild(parent.createTextNode(protocol));
    	    snmpserviceNode.appendChild(protocolNode);
    	}
    
    	if(oid != null){
    	    Node oidNode = parent.createElement(CHILD_ELEMENT_OID);
    	    oidNode.appendChild(parent.createTextNode(oid));
    	    snmpserviceNode.appendChild(oidNode);
    	}
    
    	if(community != null){
    	    Node communityNode = parent.createElement(CHILD_ELEMENT_COMMUNITY);
    	    communityNode.appendChild(parent.createTextNode(community));
    	    snmpserviceNode.appendChild(communityNode);
    	}
    
    	if(command != null){
    	    Node commandNode = parent.createElement(CHILD_ELEMENT_COMMAND);
    	    commandNode.appendChild(parent.createTextNode(command));
    	    snmpserviceNode.appendChild(commandNode);	    
    	}
    	return snmpserviceNode;
    }
}
