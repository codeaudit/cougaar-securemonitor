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
 *  The UserId class provides specific information about a user.  More
 *  than one UserId can be used within the User class to indicate
 *  attempts to transition from one user to another, or to provide
 *  complete information about a user's (or process') privileges.
 *
 *  The UserId class is composed of two aggregate classes, as shown in
 *  Figure 4.16.
 *
 *                  +--------------+
 *                  |    UserId    |
 *                  +--------------+       0..1 +--------+
 *                  | STRING ident |<>----------|  name  |
 *                  | ENUM type    |            +--------+
 *                  |              |       0..1 +--------+
 *                  |              |<>----------| number |
 *                  |              |            +--------+
 *                  +--------------+
 *
 *                    Figure 4.16 - The UserId Class
 *
 *  The aggregate classes that make up UserId are:
 *
 *  name
 *     Zero or one.  STRING.  A user or group name.
 *
 *  number
 *     Zero or one.  INTEGER.  A user or group number.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.idtype               "
 *         ( current-user | original-user | target-user | user-privs |
 *           current-group | group-privs | other-privs )
 *     "&gt
 *     &lt!ELEMENT UserId                        (
 *         name?, number?
 *     )&gt
 *     &lt!ATTLIST UserId
 *         ident               CDATA                   '0'
 *         type                %attvals.idtype;        'original-user'
 *     &gt
 *
 *  The UserId class has two attributes:
 *
 *  ident
 *     Optional.  A unique identifier for the user id.
 *
 *  type
 *     Optional.  The type of user information represented.  The
 *     permitted values for this attribute are shown below.  The default
 *     value is "original-user".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    current-user       The current user id being used by the
 *                               user or process.  On Unix systems, this
 *                               would be the "real" user id, in general.
 *       1    original-user      The actual identity of the user or
 *                               process being reported on.  On those
 *                               systems that (a) do some type of
 *                               auditing and (b) support extracting a
 *                               user id from the "audit id" token, that
 *                               value should be used.  On those systems
 *                               that do not support this, and where the
 *                               user has logged into the system, the
 *                               "login id" should be used.
 *       2    target-user        The user id the user or process is
 *                               attempting to become.  This would apply,
 *                               on Unix systems for example, when the
 *                               user attempts to use "su," "rlogin,"
 *                               "telnet," etc.
 *       3    user-privs         Another user id the user or process has
 *                               the ability to use, or a user id assoc-
 *                               iated with a file permission.  On Unix
 *                               systems, this would be the "effective"
 *                               user id in a user or process context,
 *                               and the owner permissions in a file
 *                               context.  Multiple UserId elements of
 *                               this type may be used to specify a list
 *                               of privileges.
 *       4    current-group      The current group id (if applicable)
 *                               being used by the user or process.  On
 *                               Unix systems, this would be the "real"
 *                               group id, in general.
 *       5    group-privs        Another group id the group or process
 *                               has the ability to use, or a group id
 *                               associated with a file permission.  On
 *                               Unix systems, this would be the "effect-
 *                               ive" group id in a group or process
 *                               context, and the group permissions in a
 *                               file context.  On BSD-derived Unix
 *                               systems, multiple UserId elements of
 *                               this type would be used to include all 
 *                               the group ids on the "group list."
 *       6    other-privs        Not used in a user, group, or process
 *                               The file permissions assigned to users
 *                               who do not match either the user or
 *                               group permissions on the file.  On Unix
 *                               systems, this would be the "world"
 *                               permissions.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class UserId implements XMLSerializable {

  private String name;
  private Integer number;

  //attributes
  private String ident;
  private String type;

  private static final String ATTRIBUTE_TYPE = "type";
  private static final String CHILD_ELEMENT_NAME = "name";
  private static final String CHILD_ELEMENT_NUMBER = "number";
  
  //constants
  public static final String ELEMENT_NAME        = "UserId";
  public static final String CURRENT_USER        = "current-user";
  public static final String ORIGINAL_USER       = "original-user";
  public static final String TARGET_USER         = "target-user";
  public static final String USER_PRIVS          = "user-privs";
  public static final String CURRENT_GROUP       = "current-group";
  public static final String GROUP_PRIVS         = "group-privs";
  public static final String OTHER_PRIVS         = "other-privs";
  
  //getters and setters

  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public Integer getNumber(){
    return number;
  }
  public void setNumber(Integer inNumber){
    number = inNumber;
  }
    

  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }

  public String getType(){
    return type;
  }
  public void setType(String inType){
    type = inType;
  }
   /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  Name
   *  Number
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
    boolean arenumberequal=false;
    boolean aretypeequal=true;
    UserId userid;
    if(anObject==null) {
      return equals;
    }
    if(anObject instanceof UserId) {
      userid=(UserId)anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue=userid.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arenameequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenameequal=true;
      }
      /*
      myvalue=this.getType();
      invalue=userid.getType();
      if( (myvalue!=null) && (invalue!=null) ) {
	if(myvalue.trim().equals(invalue.trim())) {
	  aretypeequal=true;
	}
      }
      else if((myvalue==null) && (invalue==null)) {
	aretypeequal=true;
      }
      */
      if((this.getNumber()!=null) && (userid.getNumber()!=null)) {
      	if(this.getNumber().intValue()==userid.getNumber().intValue()) {
      	  arenumberequal=true;
      	}
      }
      else if((this.getNumber()==null) && (userid.getNumber()==null)) {
	      arenumberequal=true;
      }
      if( arenameequal && arenumberequal  && aretypeequal ) {
	      equals=true;
      }
    }
    return equals;
  }

  /**Creates an object with all fields null.
   */
  public UserId(){
    this(null, null, null, null);
  }

  /**Copies arguments into corresponding fields.
   */
  public UserId(String inName, Integer inNumber, 
		String inIdent, String inType){
    name = inName;
    if (inNumber != null) number = new Integer(inNumber.intValue());
    else number = null;
    ident = inIdent;
    type = inType;

  }

  /**Creates an object from the XML Node containing the XML version of this object.
     This method will look for the appropriate tags to fill in the fields. If it cannot find
     a tag for a particular field, it will remain null.
  */

  public UserId(Node node){


    Node nameNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NAME);
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node numNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NUMBER);
    if (numNode == null) number=null;
    else number = new Integer(XMLUtils.getAssociatedString(numNode));

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

    Node typeNode = nnm.getNamedItem(ATTRIBUTE_TYPE);
    if (typeNode == null) type=null;
    else type = typeNode.getNodeValue();
  }

  public Node convertToXML(Document parent){

    Element useridNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      useridNode.setAttribute(ATTRIBUTE_IDENT, ident);
    if(type != null)
      useridNode.setAttribute(ATTRIBUTE_TYPE, type);


    if(name != null){
      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
      nameNode.appendChild(parent.createTextNode(name));
      useridNode.appendChild(nameNode);
    }
    if(number != null){
      Node numNode = parent.createElement(CHILD_ELEMENT_NUMBER);
      numNode.appendChild(parent.createTextNode(number.toString()));
      useridNode.appendChild(numNode);
    }
    return useridNode;
  }
}
