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
 * The Address class is used to represent network, hardware, and
 * application addresses.
 *
 * The Address class is composed of two aggregate classes, as shown in
 * Figure 4.14.
 *
 *              +------------------+
 *              |     Address      |
 *              +------------------+            +---------+
 *              | STRING ident     |<>----------| address |
 *              | ENUM category    |            +---------+
 *              | STRING vlan-name |       0..1 +---------+
 *              | INTEGER vlan-num |<>----------| netmask |
 *              |                  |            +---------+
 *              +------------------+
 *
 *                    Figure 4.14 - The Address Class
 *
 * The aggregate classes that make up Address are:
 *
 *  address
 *     Exactly one.  STRING.  The address information.  The format of
 *     this data is governed by the category attribute.
 *
 *  netmask
 *     Zero or one.  STRING.  The network mask for the address, if
 *     appropriate.
 *
 * This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.addrcat              "
 *         ( unknown | atm | e-mail | lotus-notes | mac | sna | vm |
 *           ipv4-addr | ipv4-addr-hex | ipv4-net | ipv4-net-mask |
 *           ipv6-addr | ipv6-addr-hex | ipv6-net | ipv6-net-mask )
 *       "&gt
 *     &lt!ELEMENT Address                       (
 *         address, netmask?
 *       )&gt
 *     &lt!ATTLIST Address
 *         ident               CDATA                   '0'
 *         category            %attvals.addrcat;       'unknown'
 *         vlan-name           CDATA                   #IMPLIED
 *         vlan-num            CDATA                   #IMPLIED
 *       &gt
 *
 * The Address class has four attributes:
 *
 *  ident
 *     Optional.  A unique identifier for the address, see Section 3.4.9.
 *
 *  category
 *     Optional.  The type of address represented.  The permitted values
 *     for this attribute are shown below.  The default value is
 *     "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            Address type unknown
 *       1    atm                Asynchronous Transfer Mode network
 *                               address
 *       2    e-mail             Electronic mail address (RFC 822)
 *       3    lotus-notes        Lotus Notes e-mail address
 *       4    mac                Media Access Control (MAC) address
 *       5    sna                IBM Shared Network Architecture (SNA)
 *                               address
 *       6    vm                 IBM VM ("PROFS") e-mail address
 *       7    ipv4-addr          IPv4 host address in dotted-decimal
 *                               notation (a.b.c.d)
 *       8    ipv4-addr-hex      IPv4 host address in hexadecimal
 *                               notation
 *       9    ipv4-net           IPv4 network address in dotted-decimal
 *                               notation, slash, significant bits
 *                               (a.b.c.d/nn)
 *      10    ipv4-net-mask      IPv4 network address in dotted-decimal
 *                               notation, slash, network mask in dotted-
 *                               decimal notation (a.b.c.d/w.x.y.z)
 *      11    ipv6-addr          IPv6 host address
 *      12    ipv6-addr-hex      IPv6 host address in hexadecimal
 *                               notation
 *      13    ipv6-net           IPv6 network address, slash, significant
 *                               bits
 *      14    ipv6-net-mask      IPv6 network address, slash, network
 *                               mask
 *
 *  vlan-name
 *     Optional.  The name of the Virtual LAN to which the address
 *     belongs.
 *
 *  vlan-num
 *     Optional.  The number of the Virtual LAN to which the address
 *     belongs.
 * </pre>   
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Address implements XMLSerializable{

    // elements
    private String address;
    private String netmask;
    // attributes
    private String ident;
    private String category;
    private String vlan_name;
    private Integer vlan_num;
    // element and attribute names
    private static final String ATTRIBUTE_CATEGORY = "category";

    private static final String CHILD_ELEMENT_ADDRESS = "address";
    private static final String CHILD_ELEMENT_NETMASK = "netmask";
    private static final String CHILD_ELEMENT_VLAN_NAME = "vlan_name";
    private static final String CHILD_ELEMENT_VLAN_NUM = "vlan_num";
    
    public static final String ELEMENT_NAME    = "Address";
  
    // category constants
    public static final String UNKNOWN         = "unknown";
    public static final String ATM             = "atm";
    public static final String E_MAIL          = "e-mail";
    public static final String LOTUS_NOTES     = "lotus-notes";
    public static final String MAC             = "mac";
    public static final String SNA             = "sna";
    public static final String VM              = "vm";
    public static final String IPV4_ADDR       = "ipv4-addr";
    public static final String IPV4_ADDR_HEX   = "ipv4-addr-hex";
    public static final String IPV4_NET        = "ipv4-net";
    public static final String IPV4_NET_MASK   = "ipv4-net-mask";
    public static final String IPV6_ADDR       = "ipv6-addr";
    public static final String IPV6_ADDR_HEX   = "ipv6-addr-hex";
    public static final String IPV6_NET        = "ipv6-net";
    public static final String IPV6_NET_MASK   = "ipv6-addr-net-mask";
    /**
     * Used to represent some url (category isn't in the specification).
     */
    public static final String URL_ADDR        = "url";
    
    public String getAddress(){
	    return address;
    }
    public void setAddress(String inAddress){
	    address = inAddress;
    }
    public String getNetmask(){
	    return netmask;
    }
    public void setNetmask(String inNetmask){
	    netmask = inNetmask;
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
    public String getVlan_name(){
	    return vlan_name;
    }
    public void setVlan_Name(String inVlan_Name){
	    vlan_name = inVlan_Name;
    }
    public Integer getVlan_num(){
	    return vlan_num;
    }
    public void setVlan_Num(Integer inVlan_Num){
	    vlan_num = inVlan_Num;
    }
   
  /**
   * Example of an equals method.
   * <pre>  
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  Addresses
   *  Name
   * <b>
   * NOTE: This is specific to how systems use IDMEF messages and
   *       what it means when two objects are equivalent.  For
   *       example, equivalence may mean a subset of the objects
   *       attributes.  It's advised that this method is modified
   *       for your particular environment.
   * </b>
   * </pre>
   */
  public boolean equals(Object anObject) {
    boolean equals=false;
    boolean areaddressequal=false;
    boolean arenetmaskequal=true;
    boolean arecategoryequal=false;
    boolean arevlannameequal=true;
    boolean arevlannumequal=true;
    Address inaddress;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof Address) {
      inaddress=(Address) anObject;
      String invalue;
      String myvalue;
      invalue=inaddress.getAddress();
      myvalue=this.getAddress();
      if((myvalue!=null)&&(invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        areaddressequal=true;
	      }
      }
      else if((myvalue==null)&&(invalue==null)) {
	      areaddressequal=true;
      }
      /*
      invalue=inaddress.getNetmask();
      myvalue=this.getNetmask();
      if((myvalue!=null) && (invalue!=null)){
	      if(myvalue.trim().equals(invalue.trim())) {
	        arenetmaskequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)){
	      arenetmaskequal=true;
      }
      */
      invalue=inaddress.getCategory();
      myvalue=this.getCategory();
      if((myvalue!=null) &&(invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arecategoryequal=true;
  	    }
      }
      else if((myvalue==null) &&(invalue==null)) {
	      arecategoryequal=true;
      }
      /*
      invalue=inaddress.getVlan_name();
      myvalue=this.getVlan_name();
      if((myvalue!=null) && (invalue!=null)) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arevlannameequal=true; 
	      }
      }
      else if( (myvalue==null) &&(invalue==null)) {
	      arevlannameequal=true;
      }
      if((this.getVlan_num()!=null) && (inaddress.getVlan_num()!=null)) {
	      if(this.getVlan_num().intValue()==inaddress.getVlan_num().intValue()) {
	        arevlannumequal=true;
	      }
      }
      else if((this.getVlan_num()==null) && (inaddress.getVlan_num()==null)) {
	      arevlannumequal=true;
      }
      */
      if(areaddressequal && arenetmaskequal &&  
         arecategoryequal && arevlannameequal && 
         arevlannumequal) {
	      equals=true;
      }
      
    }
    return equals;
  }
 
    /**
     * Creates an object with all fields null.
     */
    public Address(){
	    this(null, null, null, null, null, null);
    }

    /**
     * Copies arguments into corresponding fields.
     */
    public Address(String inAddress, String inNetmask, String inIdent, 
		   String inCategory, String inVlan_name, Integer inVlan_num){
	    address = inAddress;
	    netmask = inNetmask;
	    ident = inIdent;
	    category = inCategory;
	    vlan_name = inVlan_name;
	    if(inVlan_num!=null) vlan_num = new Integer (inVlan_num.intValue()); 
	    else vlan_num=null;
    }
    
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public Address(Node node){
	    Node addrNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_ADDRESS);
	    if (addrNode == null) address = null;
	    else address = XMLUtils.getAssociatedString(addrNode);

	    Node maskNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NETMASK);
	    if (maskNode == null) netmask = null;
	    else netmask = XMLUtils.getAssociatedString(maskNode);
	    
  	  NamedNodeMap nnm = node.getAttributes();
	    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
	    if(identNode == null) ident=null;
	    else ident = identNode.getNodeValue();

    	Node categoryNode = nnm.getNamedItem(ATTRIBUTE_CATEGORY);
	    if (categoryNode == null) category=null;
	    else category = categoryNode.getNodeValue();

  	  Node vlanNameNode = nnm.getNamedItem(CHILD_ELEMENT_VLAN_NAME);
	    if (vlanNameNode == null) vlan_name=null;
	    else vlan_name = vlanNameNode.getNodeValue();

	    Node vlanNumNode = nnm.getNamedItem(CHILD_ELEMENT_VLAN_NUM);
	    if (vlanNumNode == null) vlan_num=null;
	    else vlan_num = new Integer(vlanNumNode.getNodeValue());
    }

    public Node convertToXML(Document parent){
	    Element addressNode = parent.createElement(ELEMENT_NAME);
	    if(ident != null)
	      addressNode.setAttribute(ATTRIBUTE_IDENT, ident);
	    if(category != null)
	      addressNode.setAttribute(ATTRIBUTE_CATEGORY, category);
	    if(vlan_name != null)
	      addressNode.setAttribute(CHILD_ELEMENT_VLAN_NAME, vlan_name);
	    if(vlan_num != null)
	      addressNode.setAttribute(CHILD_ELEMENT_VLAN_NUM, vlan_num.toString() );
	      
	    if(address != null){
	      Node addrNode = parent.createElement(CHILD_ELEMENT_ADDRESS);
	      addrNode.appendChild(parent.createTextNode(address));
	      addressNode.appendChild(addrNode);
	    }
	
	    if(netmask != null){
	      Node maskNode = parent.createElement(CHILD_ELEMENT_NETMASK);
	      maskNode.appendChild(parent.createTextNode(netmask));
	      addressNode.appendChild(maskNode);
	    }
	    return addressNode;
    }
}
