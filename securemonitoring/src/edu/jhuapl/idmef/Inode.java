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
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * <pre>
 *  The Inode class is used to represent the additional information
 *  contained in a Unix file system i-node.
 *
 *  The Inode class is composed of six aggregate classes, as shown 
 *  below.
 *
 *              +--------------+
 *              |    Inode     |
 *              +--------------+            +----------------+
 *              |              |<>----------|   change-time  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|     number     |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|  major-device  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------|  minor-device  |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------| c-major-device |
 *              |              |            +----------------+
 *              |              |            +----------------+
 *              |              |<>----------| c-minor-device |
 *              |              |            +----------------+
 *              +--------------+
 *
 *  The aggregate classes that make up Inode are:
 *
 *  change-time
 *     Zero or one.  DATETIME.  The time of the last inode change, given
 *     by the st_ctime element of "struct stat".
 *
 *  number
 *     Zero or one.  INTEGER.  The inode number.
 *
 *  major-device
 *     Zero or one.  INTEGER.  The major device number of the device the
 *     file resides on.
 *
 *  minor-device
 *     Zero or one.  INTEGER.  The minor device number of the device the
 *     file resides on.
 *
 *  c-major-device
 *     Zero or one.  INTEGER.  The major device of the file itself, if it
 *     is a character special device.
 *
 *  c-minor-device
 *     Zero or one.  INTEGER.  The minor device of the file itself, if it
 *     is a character special device.
 *
 *  Note that <number>, <major-device>, and <minor-device> must be given
 *  together, and the <c-major-device> and <c-minor-device> must be given
 *  together.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Inode                         (
 *         change-time?, (number, major-device, minor-device)?,
 *         (c-major-device, c-minor-device)?
 *     )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Inode implements XMLSerializable {
    
    private static final String CHILD_ELEMENT_CHANGE_TIME = "change-time";
    private static final String CHILD_ELEMENT_NUMBER = "number";
    private static final String CHILD_ELEMENT_MAJOR_DEVICE = "major-device";
    private static final String CHILD_ELEMENT_MINOR_DEVICE = "minor-device";
    private static final String CHILD_ELEMENT_C_MAJOR_DEVICE = "c-major-device";
    private static final String CHILD_ELEMENT_C_MINOR_DEVICE = "c-minor-device";
    
    public static final String ELEMENT_NAME = "Inode";
    
    public Inode( Date changeTime, Integer number, Integer majorDevice, Integer minorDevice ){
        m_changeTime = changeTime;
        m_number = number;
        m_majorDevice = majorDevice;
        m_minorDevice = minorDevice;
    }
    
    public Inode( Date changeTime, Integer cMajorDevice, Integer cMinorDevice ){
        m_changeTime = changeTime;
        m_cMajorDevice = cMajorDevice;
        m_cMinorDevice = cMinorDevice;
    }
    
    public Inode( Node node ){
        Node numberNode = XMLUtils.GetNodeForName( node, 
                                CHILD_ELEMENT_NUMBER );
        Node majorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_MAJOR_DEVICE );
        Node minorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_MINOR_DEVICE );
        Node cMajorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_C_MAJOR_DEVICE );
        Node cMinorDeviceNode = XMLUtils.GetNodeForName( node, 
                                    CHILD_ELEMENT_C_MINOR_DEVICE );
        Node changeTimeNode = XMLUtils.GetNodeForName( node,
                                    CHILD_ELEMENT_CHANGE_TIME );
        SimpleDateFormat formatter = 
                new SimpleDateFormat (IDMEFTime.DATE_FORMAT);
        
        if( changeTimeNode != null ){
            try{
                String dateStr = XMLUtils.getAssociatedString( changeTimeNode );
                m_changeTime = formatter.parse( dateStr );
            }
            catch( ParseException pe ){
                pe.printStackTrace();
            }    
        }
        
        if( ( numberNode != null ) &&
            ( majorDeviceNode != null ) &&
            ( minorDeviceNode != null ) ){
            
            String number = XMLUtils.getAssociatedString( numberNode );
            String majorDevice = XMLUtils.getAssociatedString( majorDeviceNode );
            String minorDevice = XMLUtils.getAssociatedString( minorDeviceNode );
            
            m_number = new Integer( number );
            m_majorDevice = new Integer( majorDevice );
            m_minorDevice = new Integer( minorDevice );
        }
        else if( ( cMajorDeviceNode != null ) && 
                 ( cMinorDeviceNode != null ) ){
            
            String cMajorDevice = XMLUtils.getAssociatedString( cMajorDeviceNode );
            String cMinorDevice = XMLUtils.getAssociatedString( cMinorDeviceNode );
            m_cMajorDevice = new Integer( cMajorDevice );
            m_cMinorDevice = new Integer( cMinorDevice );        
        }
    }
    
    public Date getChangeTime(){
        return m_changeTime;
    }
    public void setChangeTime( Date changeTime ){
        m_changeTime = changeTime;
    }
    
    public Integer getNumber(){
        return m_number;
    }
    public void setNumber( Integer number ){
        m_number = number;
    }
    
    public Integer getMajorDevice(){
        return m_majorDevice;
    }
    public void setMajorDevice( Integer majorDevice ){
        m_majorDevice = majorDevice;
    }
    
    public Integer getMinorDevice(){
        return m_minorDevice;
    }
    public void setMinorDevice( Integer minorDevice ){
        m_minorDevice = minorDevice;
    }
    
    public Integer getCMajorDevice(){
        return m_cMajorDevice;
    }
    public void setCMajorDevice( Integer cMajorDevice ){
        m_cMajorDevice = cMajorDevice;
    }
    
    public Integer getCMinorDevice(){
        return m_cMinorDevice;
    }
    public void setCMinorDevice( Integer cMinorDevice ){
        m_cMinorDevice = cMinorDevice;
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
    boolean areChangeTimeequal=false;
    boolean areCMajordeviceequal=false;
    boolean areMajordeviceequal=false;
    boolean arenumberequal=false;
    boolean areMinordeviceequal=false;
    boolean areCMinordeviceequal=false;
    Inode inNode;
    if(anObject == null) {
      return equals;
    }
    if(anObject instanceof Inode) {
      inNode=(Inode) anObject;
      Date mydate;
      Date indate;
      mydate=this.getChangeTime();
      indate=inNode.getChangeTime();
      if((mydate!=null) && (indate!=null)) {
	      if(mydate.equals(indate)) {
	        areChangeTimeequal=true;
	      }
      }
      else  if((mydate==null) && (indate==null)) {
	      areChangeTimeequal=true;
      }
      Integer myvalue;
      Integer invalue;
      myvalue=this.getNumber();
      invalue=inNode.getNumber();
      if((myvalue!=null) && (invalue!=null)) {
	      if(myvalue.equals(invalue)) {
	        arenumberequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenumberequal=true;
      }
      myvalue=this.getMajorDevice();
      invalue=inNode.getMajorDevice();
      if((myvalue!=null) && (invalue!=null)) {
	      if(myvalue.equals(invalue)) {
	        areMajordeviceequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      areMajordeviceequal=true;
      }
      myvalue=this.getMinorDevice();
      invalue=inNode.getMinorDevice();
      if((myvalue!=null) && (invalue!=null)) {
	      if(myvalue.equals(invalue)) {
	        areMinordeviceequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      areMinordeviceequal=true;
      }
      myvalue=this.getCMajorDevice();
      invalue=inNode.getCMajorDevice();
      if((myvalue!=null) && (invalue!=null)) {
      	if(myvalue.equals(invalue)) {
	        areCMajordeviceequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      areCMajordeviceequal=true;
      }
      myvalue=this.getCMinorDevice();
      invalue=inNode.getCMinorDevice();
      if((myvalue!=null) && (invalue!=null)) {
	      if(myvalue.equals(invalue)) {
	        areCMinordeviceequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      areCMinordeviceequal=true;
      }
      if( areChangeTimeequal  &&  areCMajordeviceequal &&  areMajordeviceequal 
	        && arenumberequal  && areMinordeviceequal && areCMinordeviceequal) {
	      equals=true;
      }  
    }
    return equals;
  }
   
    public Node convertToXML( Document parent ){
        Element inodeNode = parent.createElement( ELEMENT_NAME );
        Node childNode = null;
        if( m_changeTime != null ){
            String idmefTime = IDMEFTime.convertToIDMEFFormat( m_changeTime );
            childNode = parent.createElement( CHILD_ELEMENT_CHANGE_TIME );
            childNode.appendChild( parent.createTextNode( idmefTime ) );
            inodeNode.appendChild( childNode );
        }
        if( ( m_number != null ) &&
            ( m_majorDevice != null ) &&
            ( m_minorDevice != null ) ){
            childNode = parent.createElement( CHILD_ELEMENT_NUMBER );
            childNode.appendChild( parent.createTextNode( m_number.toString() ) );
            inodeNode.appendChild( childNode );

            childNode = parent.createElement( CHILD_ELEMENT_MAJOR_DEVICE );
            childNode.appendChild( parent.createTextNode( m_majorDevice.toString() ) );
            inodeNode.appendChild( childNode );

            childNode = parent.createElement( CHILD_ELEMENT_MINOR_DEVICE );
            childNode.appendChild( parent.createTextNode( m_minorDevice.toString() ) );
            inodeNode.appendChild( childNode );
        }
        else if( ( m_cMajorDevice != null ) &&
                 ( m_cMinorDevice != null ) ){
            childNode = parent.createElement( CHILD_ELEMENT_C_MAJOR_DEVICE );
            childNode.appendChild( parent.createTextNode( m_cMajorDevice.toString() ) );
            inodeNode.appendChild( childNode );
        
            childNode = parent.createElement( CHILD_ELEMENT_C_MINOR_DEVICE );
            childNode.appendChild( parent.createTextNode( m_cMinorDevice.toString() ) );
            inodeNode.appendChild( childNode );
        }
        return inodeNode;
    }
    
    private Date m_changeTime;
    private Integer m_number;
    private Integer m_majorDevice;
    private Integer m_minorDevice;
    private Integer m_cMajorDevice;
    private Integer m_cMinorDevice;
     
}
