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
 *  The Source class contains information about the possible source(s) of
 *  the event(s) that generated an alert.  An event may have more than
 *  one source (e.g., in a distributed denial of service attack).
 *
 *  The Source class is composed of four aggregate classes, as shown in
 *  Figure 4.10.
 *
 *              +------------------+
 *              |      Source      |
 *              +------------------+       0..1 +---------+
 *              | STRING ident     |<>----------|  Node   |
 *              | ENUM spoofed     |            +---------+
 *              | STRING interface |       0..1 +---------+
 *              |                  |<>----------|  User   |
 *              |                  |            +---------+
 *              |                  |       0..1 +---------+
 *              |                  |<>----------| Process |
 *              |                  |            +---------+
 *              |                  |       0..1 +---------+
 *              |                  |<>----------| Service |
 *              |                  |            +---------+
 *              +------------------+
 *
 *                    Figure 4.10 - The Source Class
 *
 *  The aggregate classes that make up Source are:
 *
 *  Node
 *     Zero or one.  Information about the host or device that appears to
 *     be causing the events (network address, network name, etc.).
 *
 *  User
 *     Zero or one.  Information about the user that appears to be 
 *     causing the event(s).
 *
 *  Process
 *     Zero or one.  Information about the process that appears to be
 *     causing the event(s).
 *
 *  Service
 *     Zero or one.  Information about the network service involved in
 *     the event(s).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.yesno                "
 *         ( unknown | yes | no )
 *     "&gt
 *     &lt!ELEMENT Source                        (
 *         Node?, User?, Process?, Service?
 *     )&gt
 *     &lt!ATTLIST Source
 *         ident               CDATA                   '0'
 *         spoofed             %attvals.yesno;         'unknown'
 *         interface           CDATA                   #IMPLIED
 *     &gt
 *
 *  The Source class has three attributes:
 *
 *  ident
 *     Optional.  A unique identifier for this source.
 *
 *  spoofed
 *     Optional.  An indication of whether the source is, as far as the
 *     analyzer can determine, a decoy.  The permitted values for this
 *     attribute are shown below.  The default value is "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            Accuracy of source information unknown
 *       1    yes                Source is believed to be a decoy
 *       2    no                 Source is believed to be "real"
 *
 *  interface
 *     Optional.  May be used by a network-based analyzer with multiple
 *     interfaces to indicate which interface this source was seen on.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Source implements XMLSerializable{

  private IDMEF_Node node;
  private User user;
  private IDMEF_Process process;
  private Service service;

  //attributes
  private String ident;
  private String spoofed;
  private String networkInterface;
  
  private static final String ATTRIBUTE_SPOOFED = "spoofed";
  private static final String ATTRIBUTE_INTERFACE = "interface";
  //constants

  public static final String UNKNOWN = "unknown";
  public static final String YES = "yes";
  public static final String NO = "no";

  public static final String ELEMENT_NAME = "Source";
  
  //getters and setters

  public IDMEF_Node getNode(){
    return node;
  }
  public void setNode(IDMEF_Node inNode){
    node = inNode;
  }

  public User getUser(){
    return user;
  }
  public void setUser(User inUser){
    user = inUser;
  }


  public IDMEF_Process getProcess(){
    return process;
  }
  public void setProcess(IDMEF_Process inProcess){
    process = inProcess;
  }

  public Service getService(){
    return service;
  }
  public void setService(Service inService){
    service = inService;
  }

  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }

  public String getSpoofed(){
    return spoofed;
  }
  public void setSpoofed(String inSpoofed){
    spoofed = inSpoofed;
  }

  public String getNetworkInterface(){
    return networkInterface;
  }
  public void setNetworkInterface(String inNetworkInterface){
    networkInterface = inNetworkInterface;
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
    boolean arenodeequal=false;
    boolean areprocessequal=false;
    boolean areserviceequal=false;
    boolean areuserequal=false;
    boolean arespoofedequal=false;
    boolean areNIequal=false;
    Source inSource;
    if(anObject==null) {
      return equals;
    }
    if( anObject instanceof Source) {
      inSource=(Source)anObject;
      IDMEF_Node myNode;
      IDMEF_Node inNode;
      myNode=this.getNode();
      inNode=inSource.getNode();
      if((myNode!=null) && (inNode!=null)) {
      	if(myNode.equals(inNode)) {
      	  arenodeequal=true;
      	}
      }
      else if( (myNode==null) && (inNode==null)) {
	      arenodeequal=true;
      }
      IDMEF_Process myProcess;
      IDMEF_Process inProcess;
      myProcess=this.getProcess();
      inProcess=inSource.getProcess();
      if((myProcess!=null) && (inProcess!=null)) {
      	if(myProcess.equals(inProcess)) {
      	  areprocessequal=true;
      	}
      }
      else if( (myProcess==null) && (inProcess==null)) {
	      areprocessequal=true;
      }
      Service myService;
      Service inService;
      myService=this.getService();
      inService=inSource.getService();
      if((myService!=null) && (inService!=null)) {
      	if(myService.equals(inService)) {
      	  areserviceequal=true;
      	}
      }
      else if( (myService==null) && (inService==null)) {
	      areserviceequal=true;
      }
      User myUser;
      User inUser;
      myUser=this.getUser();
      inUser=inSource.getUser();
      if((myUser!=null) && (inUser!=null)) {
      	if(myUser.equals(inUser)) {
      	  areuserequal=true;
      	}
      }
      else if( (myUser==null) && (inUser==null)) {
	      areuserequal=true;
      }
      String myvalue;
      String invalue;
      myvalue=this.getSpoofed();
      invalue=inSource.getSpoofed();
      if((myvalue!=null) && (invalue!=null)) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arespoofedequal=true;
      	}
      }
      else if( (myvalue==null) && (invalue==null)) {
	      arespoofedequal=true;
      }
      
      myvalue=this.getNetworkInterface();
      invalue=inSource.getNetworkInterface();
      if((myvalue!=null) && (invalue!=null)) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  areNIequal=true;
      	}
      }
      else if( (myvalue==null) && (invalue==null)) {
	      areNIequal=true;
      }
      
      if( arenodeequal && areprocessequal && areserviceequal
	      && areuserequal &&  arespoofedequal &&  areNIequal ) {
	      equals=true;
      }      
    }
    return equals;     
  }

  /**
   * Copies arguments into corresponding fields.
   */
  public Source(IDMEF_Node inNode, User inUser, IDMEF_Process inProcess,
		Service inService, String inIdent, String inSpoofed, 
		String inNetowrkInterface){

    node = inNode;
    user = inUser;
    process = inProcess;
    service = inService;
    ident = inIdent;
    spoofed = inSpoofed;
    networkInterface = inNetowrkInterface;

  }
  
  /**
   * Creates an object with all fields null.
   */
  public Source(){
    this(null, null, null, null, null, null, null);
  }
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public Source (Node inNode){

    Node nodeNode =  XMLUtils.GetNodeForName(inNode, IDMEF_Node.ELEMENT_NAME);
    if (nodeNode == null) node = null;
    else node = new IDMEF_Node (nodeNode);

    Node userNode =  XMLUtils.GetNodeForName(inNode, User.ELEMENT_NAME);
    if (userNode == null) user = null;
    else user = new User (userNode);

    Node processNode =  XMLUtils.GetNodeForName(inNode, IDMEF_Process.ELEMENT_NAME);
    if (processNode == null) process = null;
    else process = new IDMEF_Process (processNode);

    Node serviceNode =  XMLUtils.GetNodeForName(inNode, Service.ELEMENT_NAME);
    if (serviceNode == null) service = null;
    else service = new Service (serviceNode);

    NamedNodeMap nnm = inNode.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node spoofedNode = nnm.getNamedItem(ATTRIBUTE_SPOOFED);
    if (spoofedNode == null) spoofed=null;
    else spoofed = spoofedNode.getNodeValue();

    Node networkInterfaceNode = nnm.getNamedItem(ATTRIBUTE_INTERFACE);
    if (networkInterfaceNode == null) networkInterface=null;
    else networkInterface = networkInterfaceNode.getNodeValue();
  }

  public Node convertToXML(Document parent){
    Element sourceNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      sourceNode.setAttribute(ATTRIBUTE_IDENT, ident);
    if(spoofed != null)
      sourceNode.setAttribute(ATTRIBUTE_SPOOFED, spoofed);
    if(networkInterface != null)
      sourceNode.setAttribute(ATTRIBUTE_INTERFACE,networkInterface);

    if(node != null){
      Node nodeNode = node.convertToXML(parent);
      sourceNode.appendChild(nodeNode);
    }
    if(user != null){
      Node userNode = user.convertToXML(parent);
      sourceNode.appendChild(userNode);
    }
    if(process != null){
      Node processNode = process.convertToXML(parent);
      sourceNode.appendChild(processNode);
    }
    if(service != null){
      Node serviceNode = service.convertToXML(parent);
      sourceNode.appendChild(serviceNode);
    }

    return sourceNode;
  }
}

