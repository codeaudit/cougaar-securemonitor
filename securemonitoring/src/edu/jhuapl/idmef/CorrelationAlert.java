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
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
/** 
 * <pre>
 *  The CorrelationAlert class carries additional information related to
 *  the correlation of alert information.  It is intended to group one or
 *  more previously-sent alerts together, to say "these alerts are all
 *  related."
 *
 *  The CorrelationAlert class is composed of two aggregate classes, as
 *  shown in Figure 4.4.
 *
 *         +------------------+
 *         |      Alert       |
 *         +------------------+
 *                 /_\
 *                  |
 *         +------------------+
 *         | CorrelationAlert |
 *         +------------------+            +-------------------+
 *         |                  |<>----------|        name       |
 *         |                  |            +-------------------+
 *         |                  |       1..* +-------------------+
 *         |                  |<>----------|    alertident     |
 *         |                  |            +-------------------+
 *         |                  |            | STRING analyzerid |
 *         |                  |            +-------------------+
 *         +------------------+
 *
 *                Figure 4.4 - The CorrelationAlert Class
 *
 *  The aggregate classes that make up CorrelationAlert are:
 *
 *  name
 *     Exactly one.  STRING.  The reason for grouping the alerts
 *     together, for example, a particular correlation method.
 *
 *  alertident
 *     One or more.  STRING.  The list of alert identifiers that are
 *     related to this alert.  Because alert identifiers are only unique
 *     across the alerts sent by a single analyzer, the optional
 *     "analyzerid" attribute of "alertident" should be used to identify
 *     the analyzer that a particular alert came from.  If the
 *     "analyzerid" is not provided, the alert is assumed to have come
 *     from the same analyzer that is sending the CorrelationAlert.
 *
 *  This is represented in the XML DTD as follows.
 *
 *     &lt!ELEMENT CorrelationAlert              (
 *         name, alertident+
 *       )&gt
 *     &lt!ELEMENT alertident          (#PCDATA) &gt
 *     &lt!ATTLIST alertident
 *         analyzerid          CDATA                   #IMPLIED
 *       &gt
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 */
public class CorrelationAlert extends Alert implements XMLSerializable{

    private String name;
    private Alertident[] alertidents;
    private static final String CHILD_ELEMENT_NAME = "name";
    
    public static final String ELEMENT_NAME = "CorrelationAlert";
    
    //getters and setters
    public String getName(){
	    return name;
    }
    public void setName(String inName){
	    name = inName;
    }

    public Alertident[] getAlertidents(){
	    return alertidents;
    }
    public void setAlertidents(Alertident[] inAlertidents){
	    alertidents = inAlertidents;
    }
    /**Copies arguments into corresponding fields.
      */
    public CorrelationAlert(Analyzer inAnalyzer, CreateTime ct, 
		     DetectTime dt, AnalyzerTime at, Source[] inSources, 
		     Target[] inTargets, Classification[] inClassifications, 
		     Assessment inAssessment, AdditionalData[] ad, String inIdent,
		     String inName,
		     Alertident[] inAlertidents){

	    super(inAnalyzer, ct, dt, at, inSources, inTargets, inClassifications, 
	          inAssessment, ad, inIdent);
	    name = inName;
	    alertidents = inAlertidents;
    }
    
    /**Creates an object with all fields null.
     */
    public CorrelationAlert(){
	    this(null, null, null, null, null, null, null, null, null,
	         null, null, null);
    }
    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
    */
    public CorrelationAlert(Node inNode){
	    super(inNode);
	    Node caNode =  XMLUtils.GetNodeForName(inNode, ELEMENT_NAME);
	    Node nameNode =  XMLUtils.GetNodeForName(caNode, CHILD_ELEMENT_NAME);
	    if (nameNode == null) name = null;
	    else name = XMLUtils.getAssociatedString(nameNode);

    	NodeList children = caNode.getChildNodes();
	    ArrayList alertidentNodes = new ArrayList();

	    for (int i=0; i<children.getLength(); i++){
	      Node finger = children.item(i);
	      if (finger.getNodeName().equals(Alertident.ELEMENT_NAME)){
		      Alertident newAlertident = new Alertident(finger);
		      alertidentNodes.add(newAlertident);
	      }
	    }

	    alertidents = new Alertident[alertidentNodes.size()];
	    for (int i=0; i< alertidentNodes.size(); i++){
	      alertidents[i] = (Alertident) alertidentNodes.get(i);
	    }
    }

    public Node convertToXML(Document parent){

	    Element correlationalertNode = parent.createElement(Alert.ELEMENT_NAME);
	    if(ident != null)
	      correlationalertNode.setAttribute(Alert.ATTRIBUTE_IDENT, ident);
	
	    if(analyzer != null){
	      Node analyzerNode = analyzer.convertToXML(parent);
	      correlationalertNode.appendChild(analyzerNode);  
	    }
	    if(createTime != null){
	      Node createTimeNode = createTime.convertToXML(parent);
	      correlationalertNode.appendChild(createTimeNode);
  	  }
	    if(detectTime != null){
	      Node detectTimeNode = detectTime.convertToXML(parent);
	      correlationalertNode.appendChild(detectTimeNode);
	    }
	    if(analyzerTime != null){
	      Node analyzerTimeNode = analyzerTime.convertToXML(parent);
	      correlationalertNode.appendChild(analyzerTimeNode);
    	}
	    if (sources != null){
	      for (int i=0; i<sources.length; i++){
		      Node currentNode = sources[i].convertToXML(parent);
		      if (currentNode != null) correlationalertNode.appendChild(currentNode);
	      }
	    }
	    if (targets != null){
	      for (int i=0; i<targets.length; i++){
		      Node currentNode = targets[i].convertToXML(parent);
		      if (currentNode != null) correlationalertNode.appendChild(currentNode);
	      }
	    }
	    if (classifications != null){
	      for (int i=0; i<classifications.length; i++){    
		      Node currentNode = classifications[i].convertToXML(parent);
		      if (currentNode != null) correlationalertNode.appendChild(currentNode);
	      }
	    }
	    if (additionalData != null){
	      for (int i=0; i<additionalData.length; i++){
		      Node currentNode = additionalData[i].convertToXML(parent);
		      if (currentNode != null) correlationalertNode.appendChild(currentNode);
	      }
	    }
	    //correlationalert-specific
	    Element correlationalertSpecificNode = parent.createElement(ELEMENT_NAME);
	    correlationalertNode.appendChild(correlationalertSpecificNode);
	    if(name != null){
	      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
	      nameNode.appendChild(parent.createTextNode(name));
	      correlationalertSpecificNode.appendChild(nameNode);
	    }
	    if (alertidents != null){
	      for (int i=0; i<alertidents.length; i++){
		      Node currentNode = alertidents[i].convertToXML(parent);
		      if (currentNode != null) correlationalertSpecificNode.appendChild(currentNode);
	      }
	    }
	    return correlationalertNode;
    }
}
