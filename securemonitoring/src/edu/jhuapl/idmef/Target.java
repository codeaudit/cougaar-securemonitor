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
 *  The Target class contains information about the possible target(s) of
 *  the event(s) that generated an alert.  An event may have more than
 *  one target (e.g., in the case of a port sweep).
 *
 *  The Target class is composed of four aggregate classes, as shown in
 *  Figure 4.11.
 *
 *              +------------------+
 *              |      Target      |
 *              +------------------+       0..1 +----------+
 *              | STRING ident     |<>----------|   Node   |
 *              | ENUM decoy       |            +----------+
 *              | STRING interface |       0..1 +----------+
 *              |                  |<>----------|   User   |
 *              |                  |            +----------+
 *              |                  |       0..1 +----------+
 *              |                  |<>----------| Process  |
 *              |                  |            +----------+
 *              |                  |       0..1 +----------+
 *              |                  |<>----------| Service  |
 *              |                  |            +----------+
 *              |                  |       0..1 +----------+
 *              |                  |<>----------| FileList |
 *              |                  |            +----------+
 *              +------------------+
 *
 *                    Figure 4.11 - The Target Class
 *
 *  The aggregate classes that make up Target are:
 *
 *  Node
 *     Zero or one.  Information about the host or device at which the
 *     event(s) (network address, network name, etc.) is being directed.
 *
 *  User
 *     Zero or one.  Information about the user at which the event(s) is
 *     being directed.
 *
 *  Process
 *     Zero or one.  Information about the process at which the event(s)
 *     is being directed.
 *
 *  Service
 *     Zero or one.  Information about the network service involved in
 *     the event(s).
 *
 *  FileList
 *     Zero or one.  Information about file(s) involved in the event(s).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.yesno                "
 *         ( unknown | yes | no )
 *     "&gt
 *     &lt!ELEMENT Target                        (
 *         Node?, User?, Process?, Service?, FileList?
 *     )&gt
 *     &lt!ATTLIST Target
 *         ident               CDATA                   '0'
 *         decoy               %attvals.yesno;         'unknown'
 *         interface           CDATA                   #IMPLIED
 *     &gt
 *
 *  The Target class has three attributes:
 *
 *  ident
 *     Optional.  A unique identifier for this target, see Section 3.4.9.
 *
 *  decoy
 *     Optional.  An indication of whether the target is, as far as the
 *     analyzer can determine, a decoy.  The permitted values for this
 *     attribute are shown below.  The default value is "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            Accuracy of target information unknown
 *       1    yes                Target is believed to be a decoy
 *       2    no                 Target is believed to be "real"
 *
 *  interface
 *     Optional.  May be used by a network-based analyzer with multiple
 *     interfaces to indicate which interface this target was seen on.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Target implements XMLSerializable {

  private IDMEF_Node node;
  private User user;
  private IDMEF_Process process;
  private Service service;
  private FileList fileList;
    
  //attributes
  private String ident;
  private String decoy;
  private String networkInterface;

  private static final String ATTRIBUTE_DECOY = "decoy";
  private static final String ATTRIBUTE_INTERFACE = "interface";
  
  //constants
  public static final String UNKNOWN = "unknown";
  public static final String YES = "yes";
  public static final String NO = "no";

  public static final String ELEMENT_NAME = "Target";
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

  public FileList getFileList(){
    return fileList;
  }
  public void setFileList( FileList inFileList ){
    fileList = inFileList;
  }
    
  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }

  public String getDecoy(){
    return decoy;
  }
  public void setDecoy(String inDecoy){
    decoy = inDecoy;
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
    boolean aredecoyequal=false;
    boolean areNIequal=false;
    Target inTarget;
    if(anObject==null) {
      return equals;
    }
    if( anObject instanceof Target) {
      inTarget=(Target)anObject;
      IDMEF_Node myNode;
      IDMEF_Node inNode;
      myNode=this.getNode();
      inNode=inTarget.getNode();
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
      inProcess=inTarget.getProcess();
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
      inService=inTarget.getService();
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
      inUser=inTarget.getUser();
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
      myvalue=this.getDecoy();
      invalue=inTarget.getDecoy();
      if((myvalue!=null) && (invalue!=null)) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  aredecoyequal=true;
      	}
      }
      else if( (myvalue==null) && (invalue==null)) {
	      aredecoyequal=true;
      }
      
      myvalue=this.getNetworkInterface();
      invalue=inTarget.getNetworkInterface();
      if((myvalue!=null) && (invalue!=null)) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  areNIequal=true;
      	}
      }
      else if( (myvalue==null) && (invalue==null)) {
	      areNIequal=true;
      }
      
      if( arenodeequal && areprocessequal && areserviceequal
	      && areuserequal &&  aredecoyequal &&  areNIequal ) {
	      equals=true;
      }
    }
    return equals; 
    
  }

  /**
   * Copies arguments into corresponding fields.
   */
  public Target(IDMEF_Node inNode, User inUser, IDMEF_Process inProcess,
		Service inService, FileList inFileList, String inIdent, String inDecoy, 
		String inNetowrkInterface){

    node = inNode;
    user = inUser;
    process = inProcess;
    service = inService;
    fileList = inFileList;
    ident = inIdent;
    decoy = inDecoy;
    networkInterface = inNetowrkInterface;

  }
  /**
   * Creates an object with all fields null.
   */
  public Target(){
    this(null, null, null, null, null, null, null, null);
  }
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public Target (Node inNode){

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

    Node fileListNode = XMLUtils.GetNodeForName( inNode, FileList.ELEMENT_NAME );
    if(fileListNode != null){
      fileList = new FileList( fileListNode );
    }
	
    NamedNodeMap nnm = inNode.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node decoyNode = nnm.getNamedItem(ATTRIBUTE_DECOY);
    if (decoyNode == null) decoy=null;
    else decoy = decoyNode.getNodeValue();

    Node networkInterfaceNode = nnm.getNamedItem(ATTRIBUTE_INTERFACE);
    if (networkInterfaceNode == null) networkInterface=null;
    else networkInterface = networkInterfaceNode.getNodeValue();
  }


  public Node convertToXML(Document parent){
    Element targetNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      targetNode.setAttribute(ATTRIBUTE_IDENT, ident);
    if(decoy != null)
      targetNode.setAttribute(ATTRIBUTE_DECOY, decoy);
    if(networkInterface != null)
      targetNode.setAttribute(ATTRIBUTE_INTERFACE,networkInterface);

    if(node != null){
      Node nodeNode = node.convertToXML(parent);
      targetNode.appendChild(nodeNode);
	    
    }
    if(user != null){
      Node userNode = user.convertToXML(parent);
      targetNode.appendChild(userNode);
	    
    }
    if(process != null){
      Node processNode = process.convertToXML(parent);
      targetNode.appendChild(processNode);
	    
    }
    if(service != null){
      Node serviceNode = service.convertToXML(parent);
      targetNode.appendChild(serviceNode);
	    
    }
    if( fileList != null ){
      targetNode.appendChild( fileList.convertToXML( parent ) );
    }
    
    return targetNode;
  }
}
