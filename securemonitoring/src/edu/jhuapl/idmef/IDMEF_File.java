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

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * <pre>
 * The File class provides specific information about a file or other
 *  file-like object that has been created, deleted, or modified on the
 *  target.  More than one File can be used within the FileList class to
 *  provide information about more than one file.  The description can
 *  provide either the file settings prior to the event or the file
 *  settings at the time of the event, as specified using the "category"
 *  attribute.
 *
 *  The File class is composed of ten aggregate classes, as shown in
 *  below.
 *
 *              +--------------+
 *              |     File     |
 *              +--------------+            +-------------+
 *              |              |<>----------|    name     |
 *              |              |            +-------------+
 *              |              |            +-------------+
 *              |              |<>----------|    path     |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| create-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| modify-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------| access-time |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|  data-size  |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|  disk-size  |
 *              |              |            +-------------+
 *              |              |       0..* +-------------+
 *              |              |<>----------| FileAccess  |
 *              |              |            +-------------+
 *              |              |       0..* +-------------+
 *              |              |<>----------|   Linkage   |
 *              |              |            +-------------+
 *              |              |       0..1 +-------------+
 *              |              |<>----------|    Inode    |
 *              |              |            +-------------+
 *              +--------------+
 *
 *  The aggregate classes that make up File are:
 *
 *  name
 *     Exactly one.  STRING.  The name of the file to which the alert
 *     applies, not including the path to the file.
 *
 *  path
 *     Exactly one.  STRING.  The full path to the file, including the
 *     name.  The path name should be represented in as "universal" a
 *     manner as possible, to facilitate processing of the alert.
 *
 *     For Windows systems, the path should be specified using the
 *     Universal Naming Convention (UNC) for remote files, and using a
 *     drive letter for local files (e.g., "C:\boot.ini").  For Unix
 *     systems, paths on network file systems should use the name of the
 *     mounted resource instead of the local mount point (e.g.,
 *     "fileserver:/usr/local/bin/foo").  The mount point can be provided
 *     using the <Linkage> element.
 *
 *  create-time
 *     Zero or one.  DATETIME.  Time the file was created.  Note that
 *     this is *not* the Unix "st_ctime" file attribute (which is not
 *     file creation time).  The Unix "st_ctime" attribute is contained
 *     in the "Inode" class. 
 *
 *  modify-time
 *     Zero or one.  DATETIME.  Time the file was last modified.
 *
 *  access-time
 *     Zero or one.  DATETIME.  Time the file was last accessed.
 *
 *  data-size
 *     Zero or one.  INTEGER.  The size of the data, in bytes.  Typically
 *     what is meant when referring to file size.  On Unix UFS file
 *     systems, this value corresponds to stat.st_size.  On Windows NTFS,
 *     this value corres- ponds to VDL.
 *
 *  disk-size
 *     Zero or one.  INTEGER.  The physical space on disk consumed by the
 *     file, in bytes.  On Unix UFS file systems, this value corresponds
 *     to 512 * stat.st_blocks.  On Windows NTFS, this value corresponds
 *     to EOF.
 *
 *  FileAccess
 *     Zero or more.  Access permissions on the file.
 *
 *  Linkage
 *     Zero or more.  File system objects to which this file is linked
 *     (other references for the file).
 *
 *  Inode
 *     Zero or one.  Inode information for this file (relevant to Unix).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.filecat              "
 *         ( current | original )
 *     "&gt
 *     &lt!ELEMENT File                          (
 *         name, path, create-time?, modify-time?, access-time?,
 *         data-size?, disk-size?, FileAccess*, Linkage*, Inode?
 *     )&gt
 *     &lt!ATTLIST File
 *         ident               CDATA                   '0'
 *         category            %attvals.filecat;       #REQUIRED
 *         fstype              CDATA                   #REQUIRED
 *     &gt
 *       
 *  The File class has three attributes:
 *
 *  ident
 *     Optional.  A unique identifier for this file.
 *
 *  category
 *     Required.  The context for the information being provided.  The
 *     permitted values are shown below.  There is no default value. 
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0     current           The file information is from after the
 *                               reported change
 *       1     original          The file information is from before the
 *                               reported change 
 *
 *  fstype
 *     Required.  The type of file system the file resides on.  The name
 *     should be specified using a standard abbreviation, e.g., "ufs",
 *     "nfs", "afs", "ntfs", "fat16", "fat32", "pcfs", "joliet", "cdfs",
 *     etc.  This attribute governs how path names and other attributes
 *     are interpreted.
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class IDMEF_File implements XMLSerializable {
 
  // category values
  public static final String CURRENT = "current";
  public static final String ORIGINAL = "original";
  
   // xml elements and attributes
  public static final String ELEMENT_NAME = "File";
  
  private static final String CHILD_ELEMENT_NAME = "name";
  private static final String CHILD_ELEMENT_PATH = "path";
  private static final String CHILD_ELEMENT_CREATE_TIME = "create-time";
  private static final String CHILD_ELEMENT_MODIFY_TIME = "modify-time";
  private static final String CHILD_ELEMENT_ACCESS_TIME = "access-time";
  private static final String CHILD_ELEMENT_DATA_SIZE = "data-size";
  private static final String CHILD_ELEMENT_DISK_SIZE = "disk-size";
  private static final String CHILD_ELEMENT_FILEACCESS = "FileAccess";
  private static final String CHILD_ELEMENT_LINKAGE = "Linkage";
  private static final String CHILD_ELEMENT_INODE = "Inode";
                    
  private static final String ATTRIBUTE_CATEGORY = "category";
  private static final String ATTRIBUTE_FSTYPE = "fstype";
     
  public IDMEF_File( String name, String path, 
		     Date createTime, Date modifyTime, Date accessTime, 
		     Integer dataSize, Integer diskSize, FileAccess []fileAccesses,
		     Linkage []linkages, Inode inode, String category,
		     String fstype, String ident ){
    m_name = name;
    m_path = path;
    m_createTime = createTime;
    m_modifyTime = modifyTime;
    m_accessTime = accessTime;
    m_dataSize = dataSize;
    m_diskSize = diskSize;
    m_fileAccesses = fileAccesses;
    m_linkages = linkages;
    m_inode = inode;
    m_category = category;
    m_fstype = fstype;
    m_ident = ident;
  }
  
  
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */   
  public IDMEF_File( Node node ){
        
    String nodeValue = null;
    SimpleDateFormat formatter = 
      new SimpleDateFormat ("yyyy-MM-dd'T'hh:mm:ss'Z'");
        
    Node nameNode =  XMLUtils.GetNodeForName( node, CHILD_ELEMENT_NAME );
    Node pathNode =  XMLUtils.GetNodeForName( node, CHILD_ELEMENT_PATH );
        
    if( nameNode != null ){
      // System.out.println( "IDMEF_File setting name" );
      m_name = XMLUtils.getAssociatedString( nameNode );
    }
    if( pathNode != null ){
      // System.out.println( "IDMEF_File setting path" );
      m_path = XMLUtils.getAssociatedString( pathNode );
    }
    Node cTimeNode =  XMLUtils.GetNodeForName( node, 
					       CHILD_ELEMENT_CREATE_TIME );
    if( cTimeNode != null ){
      try{
	      nodeValue = XMLUtils.getAssociatedString( cTimeNode );
	      m_createTime = formatter.parse( nodeValue );
      }
      catch( ParseException pe ){
	      pe.printStackTrace();
      }
    }
    Node mTimeNode =  XMLUtils.GetNodeForName( node, 
					       CHILD_ELEMENT_MODIFY_TIME );
    if( mTimeNode != null ){
      try{
	      nodeValue = XMLUtils.getAssociatedString( mTimeNode );
	      m_modifyTime = formatter.parse( nodeValue );
      }
      catch( ParseException pe ){
	      pe.printStackTrace();
      }
    }
    Node aTimeNode =  XMLUtils.GetNodeForName( node, 
					       CHILD_ELEMENT_ACCESS_TIME );
    if( aTimeNode != null ){
      try{
	      nodeValue = XMLUtils.getAssociatedString( aTimeNode );
	      m_accessTime = formatter.parse( nodeValue );
      }
      catch( ParseException pe ){
	      pe.printStackTrace();
      }
    }
    Node dataSizeNode = XMLUtils.GetNodeForName( node, 
						 CHILD_ELEMENT_DATA_SIZE );
    if( dataSizeNode != null ){
      nodeValue = XMLUtils.getAssociatedString( dataSizeNode ); 
      m_dataSize = new Integer( nodeValue );
    }
    Node diskSizeNode = XMLUtils.GetNodeForName( node, 
						 CHILD_ELEMENT_DISK_SIZE );
    if( diskSizeNode != null ){
      nodeValue = XMLUtils.getAssociatedString( diskSizeNode ); 
      m_diskSize = new Integer( nodeValue );
    }

    Node inodeNode = XMLUtils.GetNodeForName( node, 
					      CHILD_ELEMENT_INODE );
    if( inodeNode != null ){
      m_inode = new Inode( inodeNode );
    }
       
    NodeList children = node.getChildNodes();
    ArrayList fileAccesses = new ArrayList();
    ArrayList linkages = new ArrayList();

    for (int i = 0; i < children.getLength(); i++ ){
      Node child = children.item(i);
      if( child.getNodeName().equals( FileAccess.ELEMENT_NAME ) ){
	      fileAccesses.add( new FileAccess( child ) );
      }
      else if( child.getNodeName().equals( Linkage.ELEMENT_NAME ) ){
	      linkages.add( new Linkage( child ) );
      }
    }

        
    int size = fileAccesses.size();
    if( size > 0 ){
      m_fileAccesses = new FileAccess[ size ];
      for( int i = 0; i < size; i++ ){
	      m_fileAccesses[ i ] = ( FileAccess )fileAccesses.get( i );
      }    
    }
    size = linkages.size();
    if( size > 0 ){
      m_linkages = new Linkage[ size ];
      for( int i = 0; i < size; i++ ){
	      m_linkages[ i ] = ( Linkage )linkages.get( i );
      }
    }
        
    // get the attributes
    NamedNodeMap nnm = node.getAttributes();

    Node attr = nnm.getNamedItem( ATTRIBUTE_IDENT );
    if(attr != null){
      m_ident = attr.getNodeValue();
    }
    attr = nnm.getNamedItem( ATTRIBUTE_CATEGORY );
    if(attr != null){
      m_category = attr.getNodeValue();
    }
    attr = nnm.getNamedItem( ATTRIBUTE_FSTYPE );
    if(attr != null){
      m_fstype = attr.getNodeValue();
    }
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
    
  public Date getCreateTime(){
    return m_createTime;
  }
  public void setCreateTime( Date createTime ){
    m_createTime = createTime;
  }
    
  public Date getModifyTime(){
    return m_modifyTime;
  }
  public void setModifyTime( Date modifyTime ){
    m_modifyTime = modifyTime;
  }
    
  public Date getAccessTime(){
    return m_accessTime;
  }
  public void setAccessTime( Date accessTime ){
    m_accessTime = accessTime;
  }
    
  public Integer getDataSize(){
    return m_dataSize;
  }
  public void setDateSize( Integer dataSize ){
    m_dataSize = dataSize;
  }
    
  public Integer getDiskSize(){
    return m_diskSize;
  }
  public void setDiskSize( Integer diskSize ){
    m_diskSize = diskSize;
  }
    
  public FileAccess []getFileAccesses(){
    return m_fileAccesses;
  }
  public void setFileAccesses( FileAccess []fileAccesses ){
    m_fileAccesses = fileAccesses;
  }
    
  public Linkage []getLinkages(){
    return m_linkages;
  }
  public void setLinkages( Linkage []linkages ){
    m_linkages = linkages;
  }
    
  public Inode getInode(){
    return m_inode;
  }
  public void setInode( Inode inode ){
    m_inode = inode;
  }
    
  public String getIdent(){
    return m_ident;
  }
  public void setIdent( String ident ){
    m_ident = ident;
  }
    
  public String getCategory(){
    return m_category;
  }
  public void setCategory( String category ){
    m_category = category;
  }
    
  public String getFstype(){
    return m_fstype;
  }
  public void setFstype( String fstype ){
    m_fstype = fstype;
  }
  
  public boolean containsLinkage(Linkage inlinkage) {
    boolean contains=false;
    Linkage [] linkages=this.getLinkages();
    if(linkages==null) {
      return contains;
    }
    Linkage linkage;
    for(int i=0;i<linkages.length;i++) {
      linkage=linkages[i];
      if(linkage.equals(inlinkage)) {
	      contains=true;
	      return contains;
      }
    }
    return contains;
  }
  
  public boolean containsFileAccess(FileAccess inFileaccess) {
    boolean contains=false;
    FileAccess [] fileAccesses=this.getFileAccesses();
    if(fileAccesses==null) {
      return contains;
    }
    FileAccess fileaccess;
    for(int i=0;i<fileAccesses.length;i++) {
      fileaccess=fileAccesses[i];
      if(fileaccess.equals(inFileaccess)) {
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
  public boolean equals (Object anObject) {
    boolean equals=false;
    boolean arenameequal=false;
    boolean arepathequal=false;
    boolean arecategoryequal=false;
    boolean arefstypeequal=false;
    boolean arecreateTimeequal=false;
    boolean aremodifyTimeequal=false;
    boolean areaccessTimeequal=false;
    boolean aredataSizeequal=false;
    boolean arediskSizeequal=false;
    boolean arefileAccessequal=false;
    boolean arelinkageequal=false;
    boolean areinodeequal=false;
    if(anObject==null) {
      return equals;
    }
    IDMEF_File idmef_file;
    if(anObject instanceof IDMEF_File) {
      idmef_file=( IDMEF_File) anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue= idmef_file.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arenameequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenameequal=true;
      }
      
      myvalue=this.getPath();
      invalue=idmef_file.getPath();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arepathequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arepathequal=true;
      }
      
      myvalue=this.getCategory();
      invalue=idmef_file.getCategory();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arecategoryequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arecategoryequal=true;
      }
      
      myvalue=this.getFstype();
      invalue=idmef_file.getFstype();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arefstypeequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arefstypeequal=true;
      }
      Date mydate;
      Date indate;
      mydate=this.getCreateTime();
      indate=idmef_file.getCreateTime();
      if((mydate!=null) && (indate!=null)) {
	      if(mydate.equals(indate)) {
	        arecreateTimeequal=true;
	      }
      }
      else if((mydate==null) && (indate==null)) {
	      arecreateTimeequal=true;
      }
      
      mydate=this.getModifyTime();
      indate=idmef_file.getModifyTime();
      if((mydate!=null) && (indate!=null)) {
	      if(mydate.equals(indate)) {
	        aremodifyTimeequal=true;
	      }
      }
      else if((mydate==null) && (indate==null)) {
	      aremodifyTimeequal=true;
      }
      
      mydate=this.getAccessTime();
      indate=idmef_file.getAccessTime();
      if((mydate!=null) && (indate!=null)) {
	      if(mydate.equals(indate)) {
	        areaccessTimeequal=true;
	      }
      }
      else if((mydate==null) && (indate==null)) {
	      areaccessTimeequal=true;
      }
      Integer myint;
      Integer inint;
      myint=this.getDataSize();
      inint=idmef_file.getDataSize();
      if((myint!=null) && (inint!=null)) {
	      if(myint.equals(inint)) {
	        aredataSizeequal=true;
	      }
      }
      else if((myint==null) && (inint==null)) {
	      aredataSizeequal=true;
      }
      myint=this.getDiskSize();
      inint=idmef_file.getDiskSize();
      if((myint!=null) && (inint!=null)) {
	      if(myint.equals(inint)) {
	        arediskSizeequal=true;
	      }
      }
      else if((myint==null) && (inint==null)) {
	      arediskSizeequal=true;
      }
      
      FileAccess [] myfileaccess;
      FileAccess [] infileaccess;
      myfileaccess=this.getFileAccesses();
      infileaccess=idmef_file.getFileAccesses();
      if((myfileaccess!=null)&&(infileaccess!=null)) {
	      if(myfileaccess.length==infileaccess.length) {
	        FileAccess fileaccess;
	        for(int i=0;i<infileaccess.length;i++) {
	          fileaccess=infileaccess[i];
	          if(!containsFileAccess(fileaccess)) {
	            arefileAccessequal=false;
	            break;
	          }
	        }
	        arefileAccessequal=true;
	      }
      }
      else if((myfileaccess==null) && (infileaccess==null)) {
	      arefileAccessequal=true;
      }
      
      Linkage [] mylinkage;
      Linkage [] inlinkage;
      mylinkage=this.getLinkages();
      inlinkage=idmef_file.getLinkages();
      if((mylinkage!=null)&&(inlinkage!=null)) {
	      if(mylinkage.length==inlinkage.length) {
	        Linkage linkage;
	        for(int i=0;i<inlinkage.length;i++) {
	          linkage=inlinkage[i];
	          if(!containsLinkage(linkage)) {
	            arelinkageequal=false;
	            break;
	          }
	        }
	        arelinkageequal=true;
	      }
      }
      else if((mylinkage==null) && (inlinkage==null)) {
	      arelinkageequal=true;
      }
       
      if((this.getInode()!=null)&& (idmef_file.getInode()!=null)) {
	      if(this.getInode().equals(idmef_file.getInode())) {
	        areinodeequal=true;
	      }
      }
      else if((this.getInode()==null)&& (idmef_file.getInode()==null)) {
	      areinodeequal=true;
      }
      if( arenameequal && arepathequal && arecategoryequal && 
	      arefstypeequal && arecreateTimeequal && aremodifyTimeequal && 
	      areaccessTimeequal && aredataSizeequal && arediskSizeequal && 
	      arefileAccessequal && arelinkageequal && areinodeequal ) {
	        equals=true;
      }
    }
    return equals;  
  }
  
  public Node convertToXML( Document parent ){
    Element fileNode = parent.createElement( IDMEF_File.ELEMENT_NAME );
    Node node = null;
    String idmefTime = null;
    int len = 0;
    if( m_name != null ){
      node = parent.createElement( CHILD_ELEMENT_NAME );
      node.appendChild( parent.createTextNode( m_name ) );
      fileNode.appendChild( node );
    }
        
    if( m_path != null ){
      node = parent.createElement( CHILD_ELEMENT_PATH );
      node.appendChild( parent.createTextNode( m_path ) );
      fileNode.appendChild( node );
    }

    if( m_createTime != null ){
      node = parent.createElement( CHILD_ELEMENT_CREATE_TIME );
      idmefTime = IDMEFTime.convertToIDMEFFormat( m_createTime );
      node.appendChild( parent.createTextNode( idmefTime ) );
      fileNode.appendChild( node );
    }
        
    if( m_modifyTime != null ){
      node = parent.createElement( CHILD_ELEMENT_MODIFY_TIME );
      idmefTime = IDMEFTime.convertToIDMEFFormat( m_modifyTime );
      node.appendChild( parent.createTextNode( idmefTime ) );
      fileNode.appendChild( node );
    }
        
    if( m_accessTime != null ){
      node = parent.createElement( CHILD_ELEMENT_ACCESS_TIME );
      idmefTime = IDMEFTime.convertToIDMEFFormat( m_accessTime );
      node.appendChild( parent.createTextNode( idmefTime ) );
      fileNode.appendChild( node );
    }

    if( m_dataSize != null ){
      node = parent.createElement( CHILD_ELEMENT_DATA_SIZE );
      node.appendChild( parent.createTextNode( m_dataSize.toString() ) );
      fileNode.appendChild( node );
    }

    if( m_diskSize != null ){
      node = parent.createElement( CHILD_ELEMENT_DISK_SIZE );
      node.appendChild( parent.createTextNode( m_diskSize.toString() ) );
      fileNode.appendChild( node );
    }
        
    len = m_fileAccesses.length;
    for( int i = 0; i < len; i++ ){
      fileNode.appendChild( m_fileAccesses[ i ].convertToXML( parent ) );
    }
        
    len = m_linkages.length;
    for( int i = 0; i < len; i++ ){
      fileNode.appendChild( m_linkages[ i ].convertToXML( parent ) );
    }
        
    if( m_inode != null ){
      fileNode.appendChild( m_inode.convertToXML( parent ) );
    }
        
    if( m_ident != null ){
      fileNode.setAttribute( ATTRIBUTE_IDENT, m_ident );
    }
    if( m_category != null ){
      fileNode.setAttribute( ATTRIBUTE_CATEGORY, m_category );
    }
    if( m_fstype != null ){
      fileNode.setAttribute( ATTRIBUTE_FSTYPE, m_fstype );
    }
    return fileNode;   
  }
    
    
  private String m_name;
  private String m_path;
  private Date m_createTime;
  private Date m_modifyTime;
  private Date m_accessTime;
  private Integer m_dataSize;
  private Integer m_diskSize;
  private FileAccess m_fileAccesses[];
  private Linkage m_linkages[];
  private Inode m_inode;
  private String m_ident = "0";
  private String m_category;
  private String m_fstype;
}
