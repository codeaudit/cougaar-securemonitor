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
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
/** 
 * <pre>
 *  The Service class describes network services on sources and targets.
 *  It can identify services by name, port, and protocol.  When Service
 *  occurs as an aggregate class of Source, it is understood that the
 *  service is one from which activity of interest is originating; and
 *  that the service is "attached" to the Node, Process, and User
 *  information also contained in Source.  Likewise, when Service occurs
 *  as an aggregate class of Target, it is understood that the service is
 *  one to which activity of interest is being directed; and that the
 *  service is "attached" to the Node, Process, and User information also
 *  contained in Target.
 *
 *  The Service class is composed of four aggregate classes, as shown in
 *  Figure 4.18.
 *
 *               +--------------+
 *               |   Service    |
 *               +--------------+       0..1 +----------+
 *               | STRING ident |<>----------|   name   |
 *               |              |            +----------+
 *               |              |       0..1 +----------+
 *               |              |<>----------|   port   |
 *               |              |            +----------+
 *               |              |       0..1 +----------+
 *               |              |<>----------| portlist |
 *               |              |            +----------+
 *               |              |       0..1 +----------+
 *               |              |<>----------| protocol |
 *               |              |            +----------+
 *               +--------------+
 *                      /_\
 *                       |
 *                       +------------+
 *                                    |
 *                   +-------------+  |  +-------------+
 *                   | SNMPService |--+--| WebService  |
 *                   +-------------+     +-------------+
 *
 *                    Figure 4.18 - The Service Class
 *
 *  The aggregate classes that make up Service are:
 *
 *  name
 *     Zero or one.  STRING.  The name of the service.  Whenever
 *     possible, the name from the IANA list of well-known ports SHOULD
 *     be used.
 *
 *  port
 *     Zero or one.  INTEGER.  The port number being used.
 *
 *  portlist
 *     Zero or one.  PORTLIST.  A list of port numbers being used; see
 *     Section 3.4.8 of IDMEF specification draft v0.7 for formatting rules.
 *
 *  protocol
 *     Zero or one.  STRING.  The protocol being used.
 *
 *  A Service MUST be specified as either (a) a name, (b) a port, (c) a
 *  name and a port, or (d) a portlist.  The protocol is optional in all
 *  cases, but no other combinations are permitted.
 *
 *  Because DTDs do not support subclassing (see Section 3.3.4 of draft), the
 *  inheritance relationship between Service and the SNMPService and
 *  WebService subclasses shown in Figure 4.18 has been replaced with an
 *  aggregate relationship.
 *
 *  Service is represented in the XML DTD as follows:
 * 
 *     &lt!ELEMENT Service                       (
 *         ((name?, port?) | portlist), protocol?, SNMPService?,
 *         WebService?
 *      )&gt
 *     &lt!ATTLIST Service
 *         ident               CDATA                   '0'
 *     &gt
 *
 *  The Service class has one attribute:
 * 
 *  ident
 *     Optional.  A unique identifier for the service.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Service implements XMLSerializable {

  protected String name;
  protected Integer port;
  protected String portlist;
  protected String protocol;

  //attributes
  protected String ident;
  protected static final String CHILD_ELEMENT_NAME = "name";
  protected static final String CHILD_ELEMENT_PORT = "port";
  protected static final String CHILD_ELEMENT_PORTLIST = "portlist";
  protected static final String CHILD_ELEMENT_PROTOCOL = "protocol";
  
  public static final String ELEMENT_NAME = "Service";
  
  //getters and setters
  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public Integer getPort(){
    return port;
  }
  public void setPort(Integer inPort){
    port = inPort;
  }

 
  public String getPortlist(){
    return portlist;
  }
  public void setPortlist(String inPortlist){
    portlist = inPortlist;
  }

 
  public String getProtocol(){
    return protocol;
  }
  public void setProtocol(String inProtocol){
    protocol = inProtocol;
  }

 
  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }

  /**
   * Copies arguments into corresponding fields.
   */
  public Service (String inName, Integer inPort, String inPortlist, 
		  String inProtocol, String inIdent){
    name = inName;
    if (inPort != null) port = new Integer(inPort.intValue());
    else port = null;
    portlist = inPortlist;
    protocol = inProtocol;
    ident = inIdent;

  }
  /**
   * Creates an object with all fields null.
   */
  public Service(){
    this(null, null, null, null, null);

  }
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public Service (Node node){

    Node nameNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NAME);
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node portNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_PORT);
    if (portNode == null) port = null;
    else port = new Integer(XMLUtils.getAssociatedString(portNode));

    Node portlistNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_PORTLIST);
    if (portlistNode == null) portlist = null;
    else portlist = XMLUtils.getAssociatedString(portlistNode);

    Node protocolNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_PROTOCOL);
    if (protocolNode == null) protocol = null;
    else protocol = XMLUtils.getAssociatedString(protocolNode);

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

  }
  
  /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  All
   * <b>
   * NOTE: This is specific to how systems use IDMEF messages and
   *       what it means when two objects are equivalent.  For
   *       example, equivalence may mean a subset of the objects
   *       attributes.  It's advised that this method is modified
   *       for your particular environment.
   * </b>
   * </pre> 
   */
  public boolean equals( Object anObject) {
    boolean equals=false;
    boolean arenameequal=false;
    boolean areportequal=false;
    boolean areportlistequal=false;
    boolean areprotocolequal=false;
    Service service;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof Service) {
      service=(Service)anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue=service.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arenameequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenameequal=true;
      }
      myvalue=this.getPortlist();
      invalue=service.getPortlist();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  areportlistequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      areportlistequal=true;
      }
      myvalue=this.getProtocol();
      invalue=service.getProtocol();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  areprotocolequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      areprotocolequal=true;
      }
      if((this.getPort()!=null) && (service.getPort()!=null)) {
      	if(this.getPort().equals(service.getPort())) {
      	  areportequal=true;
      	}
      }
      else if((this.getPort()==null) && (service.getPort()==null)) {
	      areportequal=true;
      }
      
      if(arenameequal &&  areportlistequal && areprotocolequal && areportequal) {
	      equals=true;
      }
    }
    return equals;
    
  }

  public Node convertToXML(Document parent){

    Element serviceNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      serviceNode.setAttribute(ATTRIBUTE_IDENT, ident);
	
    if(name != null){
      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
      nameNode.appendChild(parent.createTextNode(name));
      serviceNode.appendChild(nameNode);
    }
    if(port != null){
      Node portNode = parent.createElement(CHILD_ELEMENT_PORT);
      portNode.appendChild(parent.createTextNode(port.toString()));
      serviceNode.appendChild(portNode);
    }
    if(portlist != null){
      Node portlistNode = parent.createElement(CHILD_ELEMENT_PORTLIST);
      portlistNode.appendChild(parent.createTextNode(portlist));
      serviceNode.appendChild(portlistNode);
    }
    if(protocol != null){
      Node protocolNode = parent.createElement(CHILD_ELEMENT_PROTOCOL);
      protocolNode.appendChild(parent.createTextNode(protocol));
      serviceNode.appendChild(protocolNode);
    }
    return serviceNode;
  }
}
