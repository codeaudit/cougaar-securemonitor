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

import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
/** 
 * <pre>
 *  The Node class is used to identify hosts and other network devices
 *  (routers, switches, etc.).
 *
 *  The Node class is composed of three aggregate classes, as shown in
 *  Figure 4.13.
 *
 *               +---------------+
 *               |     Node      |
 *               +---------------+       0..1 +----------+
 *               | STRING ident  |<>----------| location |
 *               | ENUM category |            +----------+
 *               |               |       0..1 +----------+
 *               |               |<>----------|   name   |
 *               |               |            +----------+
 *               |               |       0..* +----------+
 *               |               |<>----------|  Address |
 *               |               |            +----------+
 *               +---------------+         
 *
 *                     Figure 4.13 - The Node Class
 *
 *  The aggregate classes that make up Node are:
 *
 *  location
 *     Zero or one.  STRING.  The location of the equipment.
 *
 *  name
 *     Zero or one.  STRING.  The name of the equipment.  This
 *     information MUST be provided if no Address information is given.
 *
 *  Address
 *     Zero or more.  The network or hardware address of the equipment.
 *     Unless a name (above) is provided, at least one address must be
 *     specified.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.nodecat              "
 *         ( unknown | ads | afs | coda | dfs | dns | hosts | kerberos |
 *           nds | nis | nisplus | nt | wfw )
 *      "&gt
 *     &lt!ELEMENT Node                          (
 *         location?, (name | Address), Address*
 *      )&gt
 *     &lt!ATTLIST Node
 *         ident               CDATA                   '0'
 *         category            %attvals.nodecat;       'unknown'
 *     &gt
 *
 *  The Node class has two attributes:
 *
 *  ident
 *     Optional.  A unique identifier for the node.
 *
 *  category
 *     Optional.  The "domain" from which the name information was
 *     obtained, if relevant.  The permitted values for this attribute
 *     are shown below.  The default value is "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            Domain unknown or not relevant
 *       1    ads                Windows 2000 Advanced Directory Services
 *       2    afs                Andrew File System (Transarc)
 *       3    coda               Coda Distributed File System
         4    dfs                Distributed File System (IBM)
 *       5    dns                Domain Name System
 *       6    hosts              Local hosts file
 *       7    kerberos           Kerberos realm
 *       8    nds                Novell Directory Services
 *       9    nis                Network Information Services (Sun)
 *      10    nisplus            Network Information Services Plus (Sun)
 *      11    nt                 Windows NT domain
 *      12    wfw                Windows for Workgroups
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class IDMEF_Node implements XMLSerializable {

  private String location;
  private String name;    
  private Address addresses[];
  //attributes
  private String ident;
  private String category;
  private static final String CHILD_ELEMENT_LOCATION = "location";
  private static final String CHILD_ELEMENT_NAME = "name";
  
  private static final String ATTRIBUTE_CATEGORY = "category";
  
  //category constants
  public static final String UNKNOWN          = "unknown";
  public static final String ADS              = "ads";
  public static final String AFS              = "ads";
  public static final String CODA             = "coda";
  public static final String DFS              = "dfs";
  public static final String DNS              = "dns";
  public static final String HOSTS            = "hosts";
  public static final String KERBEROS         = "kerberos";
  public static final String NDS              = "nds";
  public static final String NIS              = "nis";
  public static final String NISPLUS          = "nisplus";
  public static final String NT               = "nt";
  public static final String WFW              = "wfw";

  public static final String ELEMENT_NAME = "Node";
  
  //getters and setters

  public String getLocation(){
    return location;
  }
  public void setLocation(String inLocation){
    location = inLocation;
  }

  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public Address[] getAddresses(){
    return addresses;
  }
  public void setAddresses(Address[] inAddresses){
    addresses = inAddresses;
  }

  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }

  public String getCategory(){	
    return category;
  }
  public void setCategory(String inCategory){
    category = inCategory;
  }

  public Node convertToXML(Document parent){

    Element nodeNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      nodeNode.setAttribute(ATTRIBUTE_IDENT, ident);
    if(category != null)
      nodeNode.setAttribute(ATTRIBUTE_CATEGORY, category);

    if(location != null){
      Node locNode = parent.createElement(CHILD_ELEMENT_LOCATION);
      locNode.appendChild(parent.createTextNode(location));
      nodeNode.appendChild(locNode);
	    
    }
    if(name != null){
      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
      nameNode.appendChild(parent.createTextNode(name));
      nodeNode.appendChild(nameNode);
	    
    }
    if (addresses != null){
      for (int i=0; i<addresses.length; i++){
	      Node currentNode = addresses[i].convertToXML(parent);
	      if (currentNode != null) nodeNode.appendChild(currentNode);
      }
    }


    return nodeNode;
  }
  /**
   * Creates an object with all fields null.
   */
  public IDMEF_Node (){
    this(null, null, null, null, null);
  }
  /**
   * Copies arguments into corresponding fields.
   */
  public IDMEF_Node (String inLocation, String inName, 
		     Address inAddresses[], 
		     String inIdent, String inCategory){
    location = inLocation;
    name = inName;
    addresses = inAddresses;
    ident = inIdent;
    category = inCategory;
  }
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public IDMEF_Node (Node node){
    Node locNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_LOCATION);
    if (locNode == null) location = null;
    else location = XMLUtils.getAssociatedString(locNode);

    Node nameNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NAME);
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    //get address nodes here
    NodeList children = node.getChildNodes();
    ArrayList addressNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals(Address.ELEMENT_NAME)){
	      Address newAddress = new Address(finger);
	      addressNodes.add(newAddress);
      }
    }
    addresses = new Address[addressNodes.size()];
    for (int i=0; i< addressNodes.size(); i++){
      addresses[i] = (Address) addressNodes.get(i);
    }

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node categoryNode = nnm.getNamedItem(ATTRIBUTE_CATEGORY);
    if (categoryNode == null) category=null;
    else category = categoryNode.getNodeValue();
  }
  /**
   * Check whether input Address is in this objects Address array 
   */
  public boolean containsAddress(Address anAddress) {
    boolean contains=false;
    Address [] myAddresses;
    Address address;
    if(this.getAddresses()!=null) {
      myAddresses=this.getAddresses();
      for(int i=0;i<myAddresses.length;i++) {
	      address=myAddresses[i];
	      if(address.equals(anAddress)) {
	        contains=true;
	        return contains;
	      }
      }
    }
    return contains;
  }
  
   /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  Addresses
   *  Category
   *  Name
   * 
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
    boolean areaddressesequal=false;
    boolean arecategoryequal=false;
    boolean arelocationequal=true;
    boolean arenameequal=false;
    IDMEF_Node idmefnode;
    Address[] comparingAddresses;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof IDMEF_Node) {
      idmefnode=(IDMEF_Node)anObject;
      comparingAddresses=idmefnode.getAddresses();
      if((this.getAddresses()!=null)&&(comparingAddresses!=null)) {
	      if(this.getAddresses().length==comparingAddresses.length) {
	        Address comparingaddress;
	        for(int i=0;i<comparingAddresses.length;i++) {
	          comparingaddress=comparingAddresses[i];
	          if(!containsAddress(comparingaddress)) {
  	          areaddressesequal=false;
	            break;
	          }
	        }
	        areaddressesequal=true;
	      }
      }
      String invalue;
      String myvalue;
      invalue=idmefnode.getCategory();
      myvalue=this.getCategory();
      if((myvalue!=null)&&(invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arecategoryequal=true;
	      }
      }
      else if((myvalue==null)&&(invalue==null)) {
	      arecategoryequal=true;
      }
      /*
      invalue=idmefnode.getLocation();
      myvalue=this.getLocation();
      if((myvalue!=null) &&(invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arelocationequal=true;
	      }
      }
      else if((myvalue==null) &&(invalue==null)) {
	      arelocationequal=true;
      }
      */
      invalue=idmefnode.getName();
      myvalue=this.getName();
      if((myvalue!=null) &&(invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arenameequal=true;
	      }
      }
      else if( (myvalue==null)&&(invalue==null)) {
	      arenameequal=true;
      }
      if(areaddressesequal && arecategoryequal && arelocationequal && arenameequal) {
	      equals=true;
      }
    }
    return equals;
  }
}
