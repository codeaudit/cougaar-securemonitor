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
 * Generally, every time an analyzer detects an event that it has been
 * configured to look for, it sends an Alert message to its manager(s).
 * Depending on the analyzer, an Alert message may correspond to a
 * single detected event, or multiple detected events.  Alerts occur
 * asynchronously in response to outside events.
 *
 * An Alert message is composed of several aggregate classes, as shown
 * in Figure 4.2.
 *
 *          +---------------+
 *          |    Alert      |
 *          +---------------+            +------------------+
 *          | STRING ident  |<>----------|     Analyzer     |
 *          |               |            +------------------+
 *          |               |            +------------------+
 *          |               |<>----------|    CreateTime    |
 *          |               |            +------------------+
 *          |               |       0..1 +------------------+
 *          |               |<>----------|    DetectTime    |
 *          |               |            +------------------+
 *          |               |       0..1 +------------------+
 *          |               |<>----------|   AnalyzerTime   |
 *          |               |            +------------------+
 *          |               |       0..* +------------------+
 *          |               |<>----------|      Source      |
 *          |               |            +------------------+
 *          |               |       0..* +------------------+
 *          |               |<>----------|      Target      |
 *          |               |            +------------------+
 *          |               |       1..* +------------------+
 *          |               |<>----------|  Classification  |
 *          |               |            +------------------+
 *          |               |       0..1 +------------------+
 *          |               |<>----------|    Assessment    |
 *          |               |            +------------------+
 *          |               |       0..* +------------------+
 *          |               |<>----------|  AdditionalData  |
 *          |               |            +------------------+
 *          +---------------+
 *                 /_\
 *                  |
 *                  +----+------------+-------------+
 *                       |            |             |
 *            +-------------------+   |   +-------------------+
 *            |     ToolAlert     |   |   |  CorrelationAlert |
 *            +-------------------+   |   +-------------------+
 *                                    |
 *                          +-------------------+
 *                          |   OverflowAlert   |
 *                          +-------------------+
 *
 *                     Figure 4.2 - The Alert Class
 *
 *  The aggregate classes that make up Alert are:
 *
 *  Analyzer
 *     Exactly one.  Identification information for the analyzer that
 *     originated the alert.
 *
 *  CreateTime
 *     Exactly one.  The time the alert was created.  Of the three times
 *     that may be provided with an Alert, this is the only one that is
 *     required.
 *
 *  DetectTime
 *     Zero or one.  The time the event(s) leading up to the alert was
 *     detected.  In the case of more than one event, the time the first
 *     event was detected.  In some circumstances, this may not be the
 *     same value as CreateTime.
 *
 *  AnalyzerTime
 *     Zero or one.  The current time on the analyzer (see Section 6.3).
 *
 *  Source
 *     Zero or more.  The source(s) of the event(s) leading up to the
 *     alert.
 *
 *  Target
 *     Zero or more.  The target(s) of the event(s) leading up to the
 *     alert.
 *
 *  Classification
 *     One or more.  The "name" of the alert, or other information
 *     allowing the manager to determine what it is.
 *
 *  Assessment
 *     Zero or one.  Information about the impact of the event, actions
 *     taken by the analyzer in response to it, and the analyzer's
 *     confidence in its evaluation.
 *
 *  AdditionalData
 *     Zero or more.  Information included by the analyzer that does not
 *     fit into the data model.  This may be an atomic piece of data, or
 *     a large amount of data provided through an extension to the IDMEF
 *     (see Section 5).
 *
 *  Because DTDs do not support subclassing (see Section 3.3.4), the
 *  inheritance relationship between Alert and the ToolAlert,
 *  CorrelationAlert, and OverflowAlert subclasses shown in Figure 4.2
 *  has been replaced with an aggregate relationship.
 *
 *  Alert is represented in the XML DTD as follows:*\
 *
 *     &lt!ELEMENT Alert                         (
 *         Analyzer, CreateTime, DetectTime?, AnalyzerTime?, Source*,
 *         Target*, Classification+, Assessment?, (ToolAlert |
 *         OverflowAlert | CorrelationAlert)?, AdditionalData*
 *       )&gt
 *     &lt!ATTLIST Alert
 *         ident               CDATA                   '0'
 *     &gt
 *
 *  The Alert class has one attribute:
 *
 *   ident
 *     Optional.  A unique identifier for the alert.
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7</a>.
 */
public class Alert extends IDMEF_Message {  
    // attribute value
    protected String ident;
    
    protected Analyzer analyzer; 
    protected CreateTime createTime;
    protected DetectTime detectTime;
    protected AnalyzerTime analyzerTime;
    protected Assessment assessment;    // as of draft v0.7
    
    protected Source []sources;
    protected Target []targets;
    protected Classification []classifications;
    protected AdditionalData []additionalData;
  
    // element name
    public static final String ELEMENT_NAME = "Alert";
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

    public DetectTime getDetectTime(){
	    return detectTime;
    }
    public void setDetectTime(DetectTime inDetectTime){
    	detectTime = inDetectTime;
    }

    public AnalyzerTime getAnalyzerTime(){
	    return analyzerTime;
    }
    public void setAnalyzerTime(AnalyzerTime inAnalyzerTime){
    	analyzerTime = inAnalyzerTime;
    }

    public Source[] getSources(){
	    return sources;
    }
    public void setSources(Source[] inSources){
    	sources = inSources;
    }
    public Target[] getTargets(){
	    return targets;
    }
    public void setTargets(Target[] inTargets){
	    targets = inTargets;
    }
    public Classification[] getClassifications(){
	    return classifications;
    }
    public void setClassifications(Classification[] inClassifications){
    	classifications = inClassifications;
    }
    
    public Assessment getAssessment() {
        return assessment;
    }
    public void setAssessment( Assessment inAssessment ) {
        assessment = inAssessment;
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

    public Alert( Analyzer inAnalyzer, CreateTime ct, 
		          DetectTime dt, AnalyzerTime at, Source[] inSources, 
		          Target[] inTargets, Classification[] inClassifications, 
		          Assessment inAssessment, AdditionalData[] ad, String inIdent ){
	    analyzer = inAnalyzer;
	    createTime = ct;
	    detectTime = dt;
	    analyzerTime = at;
	    sources = inSources;
	    targets = inTargets;
	    classifications = inClassifications;
	    assessment = inAssessment;
	    additionalData = ad;
	    ident = inIdent;
    }
    
    /**
     * Creates an object with all fields null.
     */
    public Alert(){
	
	    this(null, null, null, null, null, null, null, null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public Alert(Node inNode){

    	//read in the arrays of aggregate classes

	    Node analyzerNode =  XMLUtils.GetNodeForName(inNode, Analyzer.ELEMENT_NAME);
	    if (analyzerNode == null) analyzer = null;
	    else analyzer = new Analyzer (analyzerNode);

	    Node createTimeNode =  XMLUtils.GetNodeForName(inNode, CreateTime.ELEMENT_NAME);
	    if (createTimeNode == null) createTime = null;
	    else createTime = new CreateTime (createTimeNode);

    	Node detectTimeNode =  XMLUtils.GetNodeForName(inNode, DetectTime.ELEMENT_NAME);
    	if (detectTimeNode == null) detectTime = null;
    	else detectTime = new DetectTime (detectTimeNode);  

    	Node analyzerTimeNode =  XMLUtils.GetNodeForName(inNode, AnalyzerTime.ELEMENT_NAME);
    	if (analyzerTimeNode == null) analyzerTime = null;
    	else analyzerTime = new AnalyzerTime (analyzerTimeNode);
    	
    	Node assessmentNode = XMLUtils.GetNodeForName( inNode, Assessment.ELEMENT_NAME );
    	if ( assessmentNode != null ){
    	    assessment = new Assessment( assessmentNode );
    	}

    	NodeList children = inNode.getChildNodes();
    	ArrayList sourceNodes = new ArrayList();
    	ArrayList targetNodes = new ArrayList();
    	ArrayList classificationNodes = new ArrayList();
    	ArrayList additionalDataNodes = new ArrayList();

    	for (int i=0; i<children.getLength(); i++){
    	    Node finger = children.item(i);
    	    String nodeName = finger.getNodeName();
    	    if (nodeName.equals(Source.ELEMENT_NAME)){
        		Source newSource = new Source(finger);
         		sourceNodes.add(newSource);
	        }
	        else if (nodeName.equals(Target.ELEMENT_NAME)){
		        Target newTarget = new Target(finger);
        		targetNodes.add(newTarget);
      	    }
    	    else if (nodeName.equals(Classification.ELEMENT_NAME)){
	        	Classification newClassification = new Classification(finger);
		        classificationNodes.add(newClassification);
	        }    
	        else if (nodeName.equals(AdditionalData.ELEMENT_NAME)){
		        AdditionalData newAdditionalData = new AdditionalData(finger);
        		additionalDataNodes.add(newAdditionalData);
    	    }
	    }

    	sources = new Source[sourceNodes.size()];
    	for (int i=0; i< sourceNodes.size(); i++){
    	    sources[i] = (Source) sourceNodes.get(i);
    	}

    	targets = new Target[targetNodes.size()];
    	for (int i=0; i< targetNodes.size(); i++){
    	    targets[i] = (Target) targetNodes.get(i);
    	}
	

    	classifications = new Classification[classificationNodes.size()];
    	for (int i=0; i< classificationNodes.size(); i++){
    	    classifications[i] = (Classification) classificationNodes.get(i);
    	}

    	additionalData = new AdditionalData[additionalDataNodes.size()];
    	for (int i=0; i< additionalDataNodes.size(); i++){
    	    additionalData[i] = (AdditionalData) additionalDataNodes.get(i);
	    }



    	NamedNodeMap nnm = inNode.getAttributes();

    	Node identNode = nnm.getNamedItem("ident");
    	if(identNode == null) ident=null;
    	else ident = identNode.getNodeValue();
	}
    
    public Node convertToXML(Document parent){

	    Element alertNode = parent.createElement(ELEMENT_NAME);
	    if(ident != null)
	        alertNode.setAttribute(ATTRIBUTE_IDENT, ident);
	        
	    if(analyzer != null){
	        Node analyzerNode = analyzer.convertToXML(parent);
	        alertNode.appendChild(analyzerNode);    
	    }

    	if(createTime != null){
    	    Node createTimeNode = createTime.convertToXML(parent);
    	    alertNode.appendChild(createTimeNode);	    
    	}

	    if(detectTime != null){
	        Node detectTimeNode = detectTime.convertToXML(parent);
	        alertNode.appendChild(detectTimeNode);
	    }

    	if(analyzerTime != null){
    	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	        alertNode.appendChild(analyzerTimeNode);
	    
	    }

	    if (sources != null){
	        for (int i=0; i<sources.length; i++){
		        Node currentNode = sources[i].convertToXML(parent);
        		if (currentNode != null) alertNode.appendChild(currentNode);
    	    }
	    }

    	if (targets != null){
    	    for (int i=0; i<targets.length; i++){
    		    Node currentNode = targets[i].convertToXML(parent);
    		    if (currentNode != null) alertNode.appendChild(currentNode);
            }
	    }

    	if (classifications != null){
    	    for (int i=0; i<classifications.length; i++){
        		Node currentNode = classifications[i].convertToXML(parent);
	        	if (currentNode != null) alertNode.appendChild(currentNode);
	        }
	    }

    	if( assessment != null ) {
	        Node assessmentNode = assessment.convertToXML( parent );
	        alertNode.appendChild( assessmentNode );
	    }
	
    	if (additionalData != null){
	        for (int i=0; i<additionalData.length; i++){
	        	Node currentNode = additionalData[i].convertToXML(parent);
		        if (currentNode != null) alertNode.appendChild(currentNode);
	        }
	    }

    	return alertNode;
    }
}
