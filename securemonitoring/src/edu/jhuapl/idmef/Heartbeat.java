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
 *  Analyzers use Heartbeat messages to indicate their current status to
 *  managers.  Heartbeats are intended to be sent in a regular period,
 *  say every ten minutes or every hour.  The receipt of a Heartbeat
 *  message from an analyzer indicates to the manager that the analyzer
 *  is up and running; lack of a Heartbeat message (or more likely, lack
 *  of some number of consecutive Heartbeat messages) indicates that the
 *  analyzer or its network connection has failed.
 *
 *  All managers MUST support the receipt of Heartbeat messages; however,
 *  the use of these messages by analyzers is OPTIONAL.  Developers of
 *  manager software SHOULD permit the software to be configured on a
 *  per-analyzer basis to use/not use Heartbeat messages.
 *
 *  A Heartbeat message is composed of several aggregate classes, as
 *  shown in Figure 4.6.
 *
 *           +--------------+
 *           |  Heartbeat   |
 *           +--------------+            +------------------+
 *           | STRING ident |<>----------|     Analyzer     |
 *           |              |            +------------------+
 *           |              |            +------------------+
 *           |              |<>----------|    CreateTime    |
 *           |              |            +------------------+
 *           |              |       0..1 +------------------+
 *           |              |<>----------|   AnalyzerTime   |
 *           |              |            +------------------+
 *           |              |       0..* +------------------+
 *           |              |<>----------|  AdditionalData  |
 *           |              |            +------------------+
 *           +--------------+
 *
 *                   Figure 4.6 - The Heartbeat Class
 *
 *  The aggregate classes that make up Heartbeat are:
 *
 *  Analyzer
 *     Exactly one.  Identification information for the analyzer that
 *     originated the heartbeat.
 *
 *  CreateTime
 *     Exactly one.  The time the heartbeat was created.
 *
 *  AnalyzerTime
 *     Zero or one.  The current time on the analyzer
 *
 *  AdditionalData
 *     Zero or more.  Information included by the analyzer that does not
 *     fit into the data model.  This may be an atomic piece of data, or
 *     a large amount of data provided through an extension to the IDMEF.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Heartbeat                     (
 *          Analyzer, CreateTime, AnalyzerTime?, AdditionalData*
 *       )&gt
 *     &lt!ATTLIST Heartbeat
 *         ident               CDATA                   '0'
 *     &gt
 *
 *  The Heartbeat class has one attribute:
 *
 *  ident
 *     Optional.  A unique identifier for the heartbeat
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Heartbeat extends IDMEF_Message {

    private Analyzer analyzer;
    private CreateTime createTime;
    private AnalyzerTime analyzerTime;
    private AdditionalData additionalData[];

    //attributes
    protected String ident;
    
    public static final String ELEMENT_NAME = "Heartbeat";
    
    //getters and setters
    public Analyzer getAnalyzer(){
	    return analyzer;
    }
    public void setAnalyzer(Analyzer inAnalyzer){
	    analyzer = inAnalyzer;
    }
    public CreateTime getCreateTime(){
	    return createTime;
    }
    public void setCreateTime(CreateTime inCreateTime){
	    createTime = inCreateTime;
    }
    public AnalyzerTime getAnalyzerTime(){
	    return analyzerTime;
    }
    public void setAnalyzerTime(AnalyzerTime inAnalyzerTime){
	    analyzerTime = inAnalyzerTime;
    }
    public AdditionalData[] getAdditionalData(){
	    return additionalData;
    }
    public void setAdditionalData(AdditionalData[] inAdditionalData){
	    additionalData = inAdditionalData;
    }
    public String getIdent(){
	    return ident;
    }
    public void setIdent(String inIdent){
	    ident = inIdent;
    }

    /**
     * Copies arguments into corresponding fields.
     */
    public Heartbeat(Analyzer inAnalyzer, CreateTime ct, 
		     AnalyzerTime at, 
		     AdditionalData[] ad, String inIdent){

	    analyzer = inAnalyzer;
	    createTime = ct;
	    analyzerTime = at;
	    additionalData = ad;
	    ident = inIdent;
    }
    /**
     * Creates an object with all fields null.
     */
    public Heartbeat(){
	    this(null, null, null, null, null);
    }
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public Heartbeat(Node inNode){
  	  //read in the arrays of aggregate classes
	    Node analyzerNode =  XMLUtils.GetNodeForName(inNode, Analyzer.ELEMENT_NAME);
	    if (analyzerNode == null) analyzer = null;
	    else analyzer = new Analyzer (analyzerNode);
	    
    	Node createTimeNode =  XMLUtils.GetNodeForName(inNode, CreateTime.ELEMENT_NAME);
	    if (createTimeNode == null) createTime = null;
	    else createTime = new CreateTime (createTimeNode);

    	Node analyzerTimeNode =  XMLUtils.GetNodeForName(inNode, AnalyzerTime.ELEMENT_NAME);
	    if (analyzerTimeNode == null) analyzerTime = null;
	    else analyzerTime = new AnalyzerTime (analyzerTimeNode);

	    NodeList children = inNode.getChildNodes();
	    ArrayList additionalDataNodes = new ArrayList();

	    for (int i=0; i<children.getLength(); i++){
	      Node finger = children.item(i);

	      if (finger.getNodeName().equals(AdditionalData.ELEMENT_NAME)){
		      AdditionalData newAdditionalData = new AdditionalData(finger);
		      additionalDataNodes.add(newAdditionalData);
	      }
	    }

	    additionalData = new AdditionalData[additionalDataNodes.size()];
	    for (int i=0; i< additionalDataNodes.size(); i++){
	      additionalData[i] = (AdditionalData) additionalDataNodes.get(i);
	    }

	    NamedNodeMap nnm = inNode.getAttributes();
	    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
	    if(identNode == null) ident=null;
	    else ident = identNode.getNodeValue();
    }

    public Node convertToXML(Document parent){
	    Element heartbeatNode = parent.createElement(ELEMENT_NAME);
	    if(ident != null)
	      heartbeatNode.setAttribute(ATTRIBUTE_IDENT, ident);
	      
	    if(analyzer != null){
	      Node analyzerNode = analyzer.convertToXML(parent);
	      heartbeatNode.appendChild(analyzerNode);  
	    }
	    if(createTime != null){
	      Node createTimeNode = createTime.convertToXML(parent);
	      heartbeatNode.appendChild(createTimeNode);  
	    }
	    if(analyzerTime != null){
	      Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	      heartbeatNode.appendChild(analyzerTimeNode); 
	    }
	    if (additionalData != null){
	      for (int i=0; i<additionalData.length; i++){
		      Node currentNode = additionalData[i].convertToXML(parent);
		      if (currentNode != null) heartbeatNode.appendChild(currentNode);
	      }
	    }
	    return heartbeatNode;
    }
}
