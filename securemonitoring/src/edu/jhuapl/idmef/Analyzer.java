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
 * The Analyzer class identifies the analyzer from which the alert or
 * heartbeat message originates.  Only one analyzer may be encoded for
 * each alert or heartbeat, and that MUST be the analyzer at which the
 * alert or heartbeat originated.  Although the IDMEF data model does
 * not prevent the use of hierarchical intrusion detection systems
 * (where alerts get relayed up the tree), it does not provide any way
 * to record the identity of the "relay" analyzers along the path from
 * the originating analyzer to the manager that ultimately receives the
 * alert.
 *
 * The Analyzer class is composed of two aggregate classes, as shown in
 * Figure 4.8.
 *
 *            +---------------------+
 *            |      Analyzer       |
 *            +---------------------+       0..1 +---------+
 *            | STRING analyzerid   |<>----------|  Node   |
 *            | STRING manufacturer |            +---------+
 *            | STRING model        |       0..1 +---------+
 *            | STRING version      |<>----------| Process |
 *            | STRING class        |            +---------+
 *            | STRING ostype       |
 *            | STRING osversion    |
 *            +---------------------+
 *
 *                    Figure 4.8 - The Analyzer Class
 *
 * The aggregate classes that make up Analyzer are:
 *
 *  Node
 *     Zero or one.  Information about the host or device on which the
 *     analyzer resides (network address, network name, etc.).
 *
 *  Process
 *     Zero or one.  Information about the process in which the analyzer
 *     is executing.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Analyzer                      (
 *         Node?, Process?
 *       )&gt
 *     &lt!ATTLIST Analyzer
 *         analyzerid          CDATA                   '0'
 *         manufacturer        CDATA                   #IMPLIED
 *         model               CDATA                   #IMPLIED
 *         version             CDATA                   #IMPLIED
 *         class               CDATA                   #IMPLIED
 *         ostype              CDATA                   #IMPLIED
 *         osversion           CDATA                   #IMPLIED
 *      &gt
 *
 * The Analyzer class has seven attributes:
 *
 *  analyzerid
 *     Optional (but see below).  A unique identifier for the analyzer,
 *     see Section 3.4.9 of the IDMEF Specification draft v0.7.
 *
 *     This attribute is only "partially" optional.  If the analyzer
 *     makes use of the "ident" attributes on other classes to provide
 *     unique identifiers for those objects, then it MUST also provide a
 *     valid "analyzerid" attribute.  This requirement is dictated by the
 *     uniqueness requirements of the "ident" attribute (they are unique
 *     only within the context of a particular "analyzerid").  If the
 *     analyzer does not make use of the "ident" attributes however, it
 *     may also omit the "analyzerid" attribute.
 *
 *  manufacturer
 *     Optional.  The manufacturer of the analyzer software and/or
 *     hardware.
 *
 *  model
 *     Optional.  The model name/number of the analyzer software and/or
 *     hardware.
 *
 *  version
 *     Optional.  The version number of the analyzer software and/or
 *     hardware.
 *
 *  class
 *     Optional.  The class of analyzer software and/or hardware.
 *
 *  ostype
 *     Optional.  Operating system name.  On POSIX 1003.1 compliant
 *     systems, this is the value returned in utsname.sysname by the
 *     uname() system call, or the output of the "uname -s" command.
 *
 *  osversion
 *     Optional.  Operating system version.  On POSIX 1003.1 compliant
 *     systems, this is the value returned in utsname.release by the
 *     uname() system call, or the output of the "uname -r" command.
 *
 *  The "manufacturer", "model", "version", and "class" attributes'
 *  contents are vendor-specific, but may be used together to identify
 *  different types of analyzers (and perhaps make determinations about
 *  the contents to expect in other vendor-specific fields of IDMEF
 *  messages).
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 */
public class Analyzer implements XMLSerializable{
    private IDMEF_Node node;
    private IDMEF_Process process;
    
    //attributes
    private String analyzerid;
    private String manufacturer;
    private String model;
    private String version;
    private String analyzerClass;
    private String ostype;
    private String osversion;
    
    // element and attribute names
    private static final String ATTRIBUTE_ANALYZERID = "analyzerid";
    private static final String ATTRIBUTE_MANUFACTURER = "manufacturer";
    private static final String ATTRIBUTE_MODEL = "model";
    private static final String ATTRIBUTE_VERSION = "version";
    private static final String ATTRIBUTE_CLASS = "class";
    private static final String ATTRIBUTE_OSTYPE = "ostype";
    private static final String ATTRIBUTE_OSVERSION = "osversion";
    
    public static final String ELEMENT_NAME = "Analyzer";
    //getters and setters
    public IDMEF_Node getNode(){
	    return node;
    }
    public void setNode(IDMEF_Node inNode){
  	  node = inNode;
    }

    public IDMEF_Process getProcess(){
	    return process;
    }
    public void setProcess(IDMEF_Process inProcess){
	    process = inProcess;
    }

    public String getAnalyzerid(){
	    return analyzerid;
    }
    public void setAnalyzerid(String inAnalyzerid){
	    analyzerid = inAnalyzerid;
    }
    
    public String getManufacturer(){
      return manufacturer;
    }
    public void setManufacturer( String inManufacturer ){
      manufacturer = inManufacturer;
    }
    
    public String getModel(){
      return model;
    }
    public void setModel( String inModel ){
      model = inModel;
    }
    
    public String getVersion(){
      return version;
    }
    public void setVersion( String inVersion ){
      version = inVersion;
    }
    
    public String getAnalyzerClass(){
      return analyzerClass;
    }
    public void setAnalyzerClass( String inAnalyzerClass ){
      analyzerClass = inAnalyzerClass;
    }
    
    public String getOSType(){
      return ostype;
    }
    public void setOSType( String inOSType ){
      ostype = inOSType;
    }
    
    public String getOSVersion(){
      return osversion;
    }
    public void setOSVersion( String inOSVersion ){
      osversion = inOSVersion;
    }
    
    /**
     * Copies arguments into corresponding fields.
     */
    public Analyzer(IDMEF_Node inNode, IDMEF_Process inProcess, 
		    String inAnalyzerid, String inManufacturer, String inModel,
		    String inVersion, String inAnalyzerClass, String inOSType, 
		    String inOSVersion){
	    node = inNode;
	    process = inProcess;
	    analyzerid = inAnalyzerid;
	    manufacturer = inManufacturer;
      model = inModel;
      version = inVersion;
      analyzerClass = inAnalyzerClass;
      ostype = inOSType;
      osversion = inOSVersion;
    }
    
    /**
     * Creates an object with all fields null.
     */
    public Analyzer (){
	    this(null, null, null, null, null, null, null, null, null);
    }
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public Analyzer (Node inNode){
	    Node nodeNode =  XMLUtils.GetNodeForName(inNode, IDMEF_Node.ELEMENT_NAME);
	    if (nodeNode == null) node = null;
	    else node = new IDMEF_Node (nodeNode);
	    
	    Node processNode =  XMLUtils.GetNodeForName(inNode, IDMEF_Process.ELEMENT_NAME);
	    if (processNode == null) process = null;
	    else process = new IDMEF_Process (processNode);

	    NamedNodeMap nnm = inNode.getAttributes();

	    Node attribute = nnm.getNamedItem(ATTRIBUTE_ANALYZERID);
	    if(attribute != null){
	      analyzerid = attribute.getNodeValue();
      }
      attribute = nnm.getNamedItem(ATTRIBUTE_MANUFACTURER);
      if(attribute != null){
	      manufacturer = attribute.getNodeValue();
      }
      attribute = nnm.getNamedItem(ATTRIBUTE_MODEL);
      if(attribute != null){
	      model = attribute.getNodeValue();
      }
      attribute = nnm.getNamedItem(ATTRIBUTE_VERSION);
      if(attribute != null){
	      version = attribute.getNodeValue();
      }
      attribute = nnm.getNamedItem(ATTRIBUTE_CLASS);
      if(attribute != null){
	      analyzerClass = attribute.getNodeValue();
      }
      attribute = nnm.getNamedItem(ATTRIBUTE_OSTYPE);
      if(attribute != null){
	      ostype = attribute.getNodeValue();
      } 
      attribute = nnm.getNamedItem(ATTRIBUTE_OSVERSION);
      if(attribute != null){
	      osversion = attribute.getNodeValue();
      }
    }

  public Node convertToXML(Document parent){
	  Element analyzerNode = parent.createElement(ELEMENT_NAME);
	  if(analyzerid != null){
	    analyzerNode.setAttribute( ATTRIBUTE_ANALYZERID, analyzerid );
	  }
    if( manufacturer != null ){
      analyzerNode.setAttribute( ATTRIBUTE_MANUFACTURER, manufacturer );
    }
    if( model != null ){
      analyzerNode.setAttribute( ATTRIBUTE_MODEL, model );
    }
    if( version != null ){
      analyzerNode.setAttribute( ATTRIBUTE_VERSION, version );
    }
    if( analyzerClass != null ){
      analyzerNode.setAttribute( ATTRIBUTE_CLASS, analyzerClass );
    }
    if( ostype != null ){
      analyzerNode.setAttribute( ATTRIBUTE_OSTYPE, ostype );
    }
    if( osversion != null ){
      analyzerNode.setAttribute( ATTRIBUTE_OSVERSION, osversion );
    }
    
	  if(node != null){
	    Node nodeNode = node.convertToXML(parent);
	    analyzerNode.appendChild(nodeNode);  
	  }
	  if(process != null){
	    Node processNode = process.convertToXML(parent);
	    analyzerNode.appendChild(processNode); 
	  }
 
	  return analyzerNode;
  }
}
