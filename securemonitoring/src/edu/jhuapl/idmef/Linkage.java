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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * <pre>
 *  The Linkage class represents file system connections between the file
 *  described in the <File> element and other objects in the file system.
 *  For example, if the <File> element is a symbolic link or shortcut,
 *  then the <Linkage> element should contain the name of the object the
 *  link points to.  Further information can be provided about the object
 *  in the <Linkage> element with another <File> element, if appropriate.
 *
 *  The Linkage class is composed of three aggregate classes, as shown 
 *  below.
 *
 *              +--------------+
 *              |   Linkage    |
 *              +--------------+            +------+
 *              |              |<>----------| name |
 *              |              |            +------+
 *              |              |            +------+
 *              |              |<>----------| path |
 *              |              |            +------+
 *              |              |            +------+
 *              |              |<>----------| File |
 *              |              |            +------+
 *              +--------------+
 *
 *  The aggregate classes that make up Linkage are:
 *
 *  name
 *     Exactly one.  STRING.  The name of the file system object.  not
 *     including the path.
 *     
 *  path
 *     Exactly one.  STRING.  The full path to the file system object,
 *     including the name.  The path name should be represented in as
 *     "universal" a manner as possible, to facilitate processing of the
 *     alert.
 *
 *  File
 *     Exactly one.  A <File> element may be used in place of the <name>
 *     and <path> elements if additional information about the file is to
 *     be included.
 *
 *  The is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.linkcat              "
 *         ( hard-link | mount-point | reparse-point | shortcut |
 *           stream | symbolic-link )
 *     "&gt
 *     &lt!ELEMENT Linkage                       (
 *         (name, path) | File
 *     )&gt
 *     &lt!ATTLIST Linkage
 *         category            %attvals.linkcat;       #REQUIRED
 *     &gt
 *
 *  The Linkage class has one attribute:
 *
 *  category
 *     The type of object that the link describes.  The permitted values
 *     are shown below.  There is no default value.
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    hard-link          The <name> element represents another
 *                               name for this file.  This information
 *                               may be more easily obtainable on NTFS
 *                               file systems than others.
 *       1    mount-point        An alias for the directory specified by
 *                               the parent's <name> and <path> elements.
 *       2    reparse-point      Applies only to Windows; excludes
 *                               symbolic links and mount points, which
 *                               are specific types of reparse points.
 *       3    shortcut           The file represented by a Windows
 *                               "shortcut."  A shortcut is distinguished
 *                               from a symbolic link because of the
 *                               difference in their contents, which may
 *                               be of importance to the manager.
 *       4    stream             An Alternate Data Stream (ADS) in
 *                               Windows; a fork on MacOS.  Separate file
 *                               system entity that is considered an
 *                               extension of the main <File>.
 *       5    symbolic-link      The <name> element represents the file
 *                               to which the link points.
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Linkage implements XMLSerializable {
  // xml element and attribute names
  private static final String CHILD_ELEMENT_NAME = "name";
  private static final String CHILD_ELEMENT_PATH = "path";
  private static final String ATTRIBUTE_CATEGORY = "category";
  
  public static final String ELEMENT_NAME = "Linkage";
 
  // category values
  public static final String HARD_LINK = "hard-link";
  public static final String MOUNT_POINT = "mount-point";
  public static final String REPARSE_POINT = "reparse-point";
  public static final String SHORT_CUT = "shortcut";
  public static final String STREAM = "stream";
  public static final String SYMBOLIC_LINK = "symbolic-link";
    
  public Linkage( String name, String path, String category ){
    m_name = name;
    m_path = path;
    m_category = category;
  }
    
  public Linkage( IDMEF_File file, String category ){
    m_file = file;
    m_category = category;
  }
    
  public Linkage( Node node ){
    Node nameNode = XMLUtils.GetNodeForName( node, CHILD_ELEMENT_NAME );
    Node pathNode = XMLUtils.GetNodeForName( node, CHILD_ELEMENT_PATH );
    if( nameNode != null ){
      m_name = XMLUtils.getAssociatedString( nameNode );
    }
    if( pathNode != null ){
      m_path = XMLUtils.getAssociatedString( pathNode );
    }
    Node fileNode = XMLUtils.GetNodeForName( node, IDMEF_File.ELEMENT_NAME );
    if( fileNode != null ){
      m_file = new IDMEF_File( fileNode );
    }
    NamedNodeMap nnm = node.getAttributes();
    Node categoryNode = nnm.getNamedItem( ATTRIBUTE_CATEGORY );
    if( categoryNode != null ){
      m_category = categoryNode.getNodeValue();
    }
  }
    
  public String getCategory(){
    return m_category;
  }
  public void setCategory( String category ){
    m_category = category;
  }
    
  public String getName(){
    return m_name;
  }
  public void setName( String name ){
    m_name = name;
  }
    
  public String getPath(){
    return m_path;
  }
  public void setPath( String path ){
    m_path = path;
  }
    
  public IDMEF_File getFile(){
    return m_file;
  }
  public void setFile( IDMEF_File file ){
    m_file = file;
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
    boolean arecategoryequal=false;
    boolean arenameequal=false;
    boolean arepathequal=false;
    boolean areIdmefFileequal=false;
    if(anObject==null) {
      return equals;
    }
    Linkage linkage;
    if(anObject instanceof Linkage) {
      linkage=(Linkage)anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue=linkage.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
  	    if(myvalue.trim().equals(invalue.trim())) {
  	      arenameequal=true;
  	    }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenameequal=true;
      }
      myvalue=this.getPath();
      invalue=linkage.getPath();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arepathequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      arepathequal=true;
      }
      myvalue=this.getCategory();
      invalue=linkage.getCategory();
      if( (myvalue!=null) && (invalue!=null) ) {
      	if(myvalue.trim().equals(invalue.trim())) {
      	  arecategoryequal=true;
      	}
      }
      else if((myvalue==null) && (invalue==null)) {
	      arecategoryequal=true;
      }
      if((this.getFile()!=null) &&( linkage.getFile()!=null)) {
      	if(this.getFile().equals(linkage.getFile())) {
      	  areIdmefFileequal=true;
      	}
      }
      else  if((this.getFile()==null) &&( linkage.getFile()==null)) {
	      areIdmefFileequal=true;
      }
      if( arenameequal && arepathequal && arecategoryequal && areIdmefFileequal) {
	      equals=true;
      }
      
    }
    return equals;
  }
    
  public Node convertToXML( Document parent ){
    Element linkageNode = parent.createElement( ELEMENT_NAME );
    if( m_file != null ){
      linkageNode.appendChild( m_file.convertToXML( parent ) );
    }
    else if( m_name != null && m_path != null ) {
      Node nameNode = parent.createElement( CHILD_ELEMENT_NAME );
      Node pathNode = parent.createElement( CHILD_ELEMENT_PATH );
      nameNode.appendChild( parent.createTextNode( m_name ) );
      pathNode.appendChild( parent.createTextNode( m_path ) );                        
      linkageNode.appendChild( nameNode );
      linkageNode.appendChild( pathNode );
    }
        
    if( m_category != null ){
      linkageNode.setAttribute( ATTRIBUTE_CATEGORY, m_category );
    }
    return linkageNode;    
  }
    
  private String m_category;
  private String m_name;
  private String m_path;
  private IDMEF_File m_file;
    
}
