/* 
 The following passage applies to all software and text files in this distribution, 
 including this one:
 
 Copyright (c) 2002 Networks Associates Technology, Inc. under sponsorship of the 
 Defense Advanced Research Projects Agency (DARPA). 
 All Rights Reserved.
 
 Redistribution and use in source and binary forms, with or without modification, 
 are permitted provided that the following conditions are met:
 
    -> Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.

    -> Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

    -> Neither the name of the Network Associates nor the names of its 
       contributors may be used to endorse or promote products 
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
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * <pre>
 *  The FileAccess class represents the access permissions on a file.
 *  The representation is intended to be usefule across operating
 *  systems.
 *
 *  The FileAccess class is composed of two aggregate classes, as shown
 *  below.
 *
 *              +--------------+
 *              |  FileAccess  |
 *              +--------------+            +------------+
 *              |              |<>----------|   UserId   |
 *              |              |            +------------+
 *              |              |       1..* +------------+
 *              |              |<>----------| permission |
 *              |              |            +------------+
 *              +--------------+
 *
 *
 *  The aggregate classes that make up FileAccess are:
 *
 *  UserId
 *     Exactly one.  The user (or group) to which these permissions
 *     apply.  The value of the "type" attribute must be "user-privs",
 *     "group-privs", or "other-privs" as appropriate.  Other values for
 *     "type" MUST NOT be used in this context.
 *
 * permission
 *     One or more.  STRING.  Level of access allowed.  Recommended
 *     values are "noAccess", "read", "write", "execute", "delete",
 *     "executeAs", "changePermissions", and "takeOwnership".  The
 *     "changePermissions" and "takeOwnership" strings represent those
 *     concepts in Windows.  On Unix, the owner of the file always has
 *     "changePermissions" access, even if no other access is allowed for
 *     that user.  "Full Control" in Windows is represented by
 *     enumerating the permissions it contains.  The "executeAs" string
 *     represents the set-user-id and set-group-id features in Unix.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT FileAccess ( UserId, permission+ )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 * @since IDMEF Specification Draft v0.6
 */
public class FileAccess implements XMLSerializable {
  private static final String CHILD_ELEMENT_PERMISSION = "permission";
  
  public static final String ELEMENT_NAME = "FileAccess";
  
  
  /**
   * Copies arguments into corresponding fields.
   */
  public FileAccess( UserId userId, String []permissions ){
    m_userId = userId;
    m_permissions = permissions;
  }
  
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public FileAccess( Node node ){
    Node userIdNode = XMLUtils.GetNodeForName( node, UserId.ELEMENT_NAME );
    if( userIdNode != null ){
      m_userId = new UserId( userIdNode );
    }
        
    NodeList childList = node.getChildNodes();
    int len = childList.getLength();
    ArrayList permissions = new ArrayList();
    for( int i = 0; i < len; i++ ){
      Node child = childList.item( i );
      if( child.getNodeName().equals( CHILD_ELEMENT_PERMISSION ) ){
	      permissions.add( XMLUtils.getAssociatedString( child ) );
      }
    }
        
    int size = permissions.size();
    if( size > 0 ){
      m_permissions = new String[ size ];
      for( int i = 0; i < size; i++ ){
	      m_permissions[ i ] = ( String )permissions.get( i );
      }
    }
  }
    
  public UserId getUserId(){
    return m_userId;
  }
  public void setUserId( UserId userId ){
    m_userId = userId;
  }
    
  public String []getPermissions(){
    return m_permissions;
  }
  public void setPermissions( String []permissions ){
    m_permissions = permissions;
  }
  
  public boolean containsPermission(String inPermission) {
    boolean contains=false;
    String [] permissions=this.getPermissions();
    if(permissions == null) {
      return contains;
    }
    String permission;
    for(int i=0;i<permissions.length;i++) {
      permission=permissions[i];
      if(permission.trim().equals(inPermission.trim())) {
	      contains=true;
	      return contains;
      }
    }
    return contains;
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
  public boolean equals(Object anObject) {
    boolean equals=false;
    boolean areuseridequal=false;
    boolean arepermequal=false;
    if(anObject==null) {
      return equals;
    }
    FileAccess fileaccess;
    if(anObject instanceof FileAccess) {
      fileaccess=(FileAccess)anObject;
      String [] myarray;
      String [] inarray;
      myarray=this.getPermissions();
      inarray=fileaccess.getPermissions();
      if((myarray!=null)&&(inarray!=null)) {
	      if(myarray.length==inarray.length) {
	        String value;
	        for(int i=0;i<inarray.length;i++) {
	          value=inarray[i];
	          if(!containsPermission(value)) {
	            arepermequal=false;
	            break;
	          }
	        }
	        arepermequal=true;
	      }
      }
      else if((myarray==null) && (inarray==null)) {
	      arepermequal=true;
      }
      UserId myuserid;
      UserId inuserid;
      myuserid=this.getUserId();
      inuserid=fileaccess.getUserId();
      if((myuserid!=null) && (inuserid!=null)) {
	      if(myuserid.equals(inuserid)) {
	        areuseridequal=true;
      	}
      }
      else if((myarray==null) && (inarray==null)) {
	      areuseridequal=true;
      }
      if( arepermequal && areuseridequal) {
	      equals=true;
      }
    }
    return equals;
  }
  
    
  public Node convertToXML( Document parent ){
    Element fileAccessNode = parent.createElement( ELEMENT_NAME );    
    fileAccessNode.appendChild( m_userId.convertToXML( parent ) );
    int len = m_permissions.length;
    for( int i = 0; i < len; i++ ){
      Node pNode = parent.createElement( CHILD_ELEMENT_PERMISSION );
      pNode.appendChild( parent.createTextNode( m_permissions[ i ] ) );
      fileAccessNode.appendChild( pNode );
    }
    return fileAccessNode;
  }
    
  private UserId m_userId;
  private String m_permissions[];
}
