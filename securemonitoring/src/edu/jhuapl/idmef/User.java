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
 *  The User class is used to describe users.  It is primarily used as a
 *  "container" class for the UserId aggregate class, as shown in Figure
 *  4.15.
 *
 *                +---------------+
 *                |     User      |
 *                +---------------+       1..* +--------+
 *                | STRING ident  |<>----------| UserId |
 *                | ENUM category |            +--------+
 *                +---------------+
 *
 *                     Figure 4.15 - The User Class
 *
 *  The aggregate class contained in User is:
 *
 *  UserId
 *     One or more.  Identification of a user, as indicated by its type
 *     attribute.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.usercat              "
 *         ( unknown | application | os-device )
 *     "&gt
 *     &lt!ELEMENT User                          (
 *         UserId+
 *     )&gt
 *     &lt!ATTLIST User
 *         ident               CDATA                   '0'
 *         category            %attvals.usercat;       'unknown'
 *     &gt
 *
 *  The User class has two attributes:
 *
 *  ident
 *     Optional.  A unique identifier for the user.
 *
 *  category
 *     Optional.  The type of user represented.  The permitted values
 *     for this attribute are shown below.  The default value is
 *     "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            User type unknown
 *       1    application        An application user
 *       2    os-device          An operating system or device user
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class User implements XMLSerializable{

  private UserId userIds[];

  //attributes
  private String ident;
  private String category;

  private static final String ATTRIBUTE_CATEGORY = "category";
  //constants

  public static final String UNKNOWN = "unknown";
  public static final String APPLICATION = "application";
  public static final String OS_DEVICE = "os-device";

  public static final String ELEMENT_NAME = "User";
  
  //getters and setters

  public UserId[] getUserIds(){
    return userIds;
  }

  public void setUserIds(UserId[] inUserIds){
    userIds = inUserIds;
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
   /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  UserId
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
    boolean areuseridsequal=false;
    boolean arecategoryequal=true;
    User user;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof User) {
      user=(User)anObject;
      UserId [] myarray;
      UserId [] inarray;
      myarray=this.getUserIds();
      inarray=user.getUserIds();
      if((myarray!=null)&&(inarray!=null)) {
      	if(myarray.length==inarray.length) {
      	  UserId value;
      	  for(int i=0;i<inarray.length;i++) {
      	    value=inarray[i];
      	    if(!contains(value)) {
      	      areuseridsequal=false;
      	      break;
      	    }
      	  }
      	  areuseridsequal=true;
      	}
      }
      else if((myarray==null) && (inarray==null)) {
	      areuseridsequal=true;
      }
      /*
      String myvalue;
      String invalue;
      myvalue=this.getCategory();
      invalue=user.getCategory();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arecategoryequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      arecategoryequal=true;
      }
      */
      if(areuseridsequal && arecategoryequal) {
	      equals=true;
      }
    }
      return equals;
  }
   
  public boolean contains(UserId inuserid) {
    boolean contains=false;
    UserId[] userids=this.getUserIds();
    if(userids==null) {
      return contains;
    }
    UserId userid;
    for(int i=0;i<userids.length;i++) {
      userid=userids[i];
      if(userid.equals(inuserid)) {
      	contains=true;
      	return contains;
      }
    }
    return contains;
  } 
  
  /**
   * Creates an object with all fields null.
   */
  public User(){
    this(null, null, null);
  }
  /**
   * Copies arguments into corresponding fields.
   */
  public User (UserId inUserIds[], String inIdent, String inCategory){
    userIds = inUserIds;
    ident = inIdent;
    category = inCategory;
  }
  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */
  public User(Node node){
    //get userid nodes here
    NodeList children = node.getChildNodes();
    ArrayList useridNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals(UserId.ELEMENT_NAME)){
      	UserId newUserid = new UserId(finger);
      	useridNodes.add(newUserid);
      }
    }
    userIds = new UserId[useridNodes.size()];
    for (int i=0; i< useridNodes.size(); i++){
      userIds[i] = (UserId) useridNodes.get(i);
    }

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node categoryNode = nnm.getNamedItem(ATTRIBUTE_CATEGORY);
    if (categoryNode == null) category=null;
    else category = categoryNode.getNodeValue();

  }
  public Node convertToXML(Document parent){

    Element userNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      userNode.setAttribute(ATTRIBUTE_IDENT, ident);
    if(category != null)
      userNode.setAttribute(ATTRIBUTE_CATEGORY, category);


    if (userIds != null){
      for (int i=0; i<userIds.length; i++){
    	Node currentNode = userIds[i].convertToXML(parent);
    	if (currentNode != null) userNode.appendChild(currentNode);
      }
    }
    return userNode;
  }
}
