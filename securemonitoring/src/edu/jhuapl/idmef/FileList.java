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
 *  The FileList class describes files and other file-like objects on
 *  targets.  It is primarily used as a "container" class for the File
 *  aggregate class, as shown in Figure 4.21.
 *
 *                 +--------------+
 *                 |   FileList   |
 *                 +--------------+       1..* +------+
 *                 |              |<>----------| File |
 *                 |              |            +------+
 *                 +--------------+
 *
 *                    Figure 4.21 - The FileList Class
 *
 *  The aggregate class contained in FileList is:
 *
 *  File
 *     One or more.  Information about an individual file, as indicated
 *     by its "category" and "fstype" attributes (see Section 4.2.7.5.1 of draft).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT FileList ( File+ )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 * @since IDMEF Specification Draft v0.6
 */
public class FileList implements XMLSerializable {
  public static final String ELEMENT_NAME = "FileList";
    
  public FileList( IDMEF_File []files ){
    m_files = files;
  }
 
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public FileList( Node node ){
    NodeList childList = node.getChildNodes();
    ArrayList fileList = new ArrayList();
    int len = childList.getLength();
    	
    for ( int i = 0; i < len; i++ ){
      Node child = childList.item( i );
      if( child.getNodeName().equals( IDMEF_File.ELEMENT_NAME ) ){
	      // there should be one impact element
	      fileList.add( new IDMEF_File( child ) );
      }
    }
	    
    int size = fileList.size();
    if( size > 0 ){ 
      m_files = new IDMEF_File[ size ];
      for( int i = 0; i < size; i++ ){
	      m_files[ i ] = ( IDMEF_File )fileList.get( i );
      }
    }
  }
     
  public IDMEF_File []getFiles(){
    return m_files;
  }
  public void setFiles( IDMEF_File []files ){
    m_files = files;
  }
  
  public boolean contains (IDMEF_File infile) {
    boolean contains=false;
    IDMEF_File[] files=this.getFiles();
    if(files==null) {
      return contains;
    }
    IDMEF_File file;
    for(int i=0;i<files.length;i++) {
      file=files[i];
      if(file.equals(infile)) {
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
    boolean arefileListequal=false;
    FileList fileList;
    if(anObject==null) {
      return equals;
    }
    if( anObject instanceof FileList) {
      fileList=(FileList) anObject;
      IDMEF_File [] myarray;
      IDMEF_File [] inarray;
      myarray=this.getFiles();
      inarray=fileList.getFiles();
      if((myarray!=null)&&(inarray!=null)) {
	      if(myarray.length==inarray.length) {
	        IDMEF_File file;
	        for(int i=0;i<inarray.length;i++) {
	          file=inarray[i];
	          if(!contains(file)) {
	            arefileListequal=false;
	            break;
	          }
	        }
	        arefileListequal=true;
	      }
      }
      else if((myarray==null) && (inarray==null)) {
	      arefileListequal=true;
      }
      if(arefileListequal) {
	      equals=true;
      }
    }
    return equals;
  }
    
  public Node convertToXML( Document parent ) {
    Element fileListNode = parent.createElement( ELEMENT_NAME );
    int len = m_files.length;
        
    for( int i = 0; i < len; i++ ){
      fileListNode.appendChild( m_files[ i ].convertToXML( parent ) );
    }           
    return fileListNode;
  }
    
  private IDMEF_File m_files[];
}
