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
 *  The ToolAlert class carries additional information related to the use
 *  of attack tools or malevolent programs such as Trojan horses, and can
 *  be used by the analyzer when it is able to identify these tools.  It
 *  is intended to group one or more previously-sent alerts together, to
 *  say "these alerts were all the result of someone using this tool."
 *
 *  The ToolAlert class is composed of three aggregate classes, as shown
 *  in Figure 4.3.
 *
 *         +------------------+
 *         |      Alert       |
 *         +------------------+
 *                 /_\
 *                  |
 *         +------------------+
 *         |    ToolAlert     |
 *         +------------------+            +-------------------+
 *         |                  |<>----------|        name       |
 *         |                  |            +-------------------+
 *         |                  |       0..1 +-------------------+
 *         |                  |<>----------|      command      |
 *         |                  |            +-------------------+
 *         |                  |       1..* +-------------------+
 *         |                  |<>----------|    alertident     |
 *         |                  |            +-------------------+
 *         |                  |            | STRING analyzerid |
 *         |                  |            +-------------------+
 *         +------------------+   
 *
 *                   Figure 4.3 - The ToolAlert Class
 *
 *  The aggregate classes that make up ToolAlert are:
 *
 *  name
 *     Exactly one.  STRING.  The reason for grouping the alerts
 *     together, for example, the name of a particular tool.
 *
 *  command
 *     Zero or one.  STRING.  The command or operation that the tool was
 *     asked to perform, for example, a BackOrifice ping.
 *
 *  alertident
 *     One or more.  STRING.  The list of alert identifiers that are
 *     related to this alert.  Because alert identifiers are only unique
 *     across the alerts sent by a single analyzer, the optional
 *     "analyzerid" attribute of "alertident" should be used to identifyb
 *     the analyzer that a particular alert came from.  If the
 *     "analyzerid" is not provided, the alert is assumed to have come
 *     from the same analyzer that is sending the ToolAlert.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT ToolAlert                     (
 *         name, command?, alertident+
 *     )&gt
 *     &lt!ELEMENT alertident          (#PCDATA) &gt
 *     &lt!ATTLIST alertident
 *         analyzerid          CDATA                   #IMPLIED
 *     &gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class ToolAlert extends Alert implements XMLSerializable {


    private String name;
    private String command;
    private Alertident alertidents[];

    private static final String CHILD_ELEMENT_NAME = "name";
    private static final String CHILD_ELEMENT_COMMAND = "command";
    
    public static final String ELEMENT_NAME = "ToolAlert";
    
    //getters and setters
    public String getName () {
	    return name;
    }
    public void setName(String inName){
	    name = inName;
    }

    public String getCommand(){
	    return command;
    }
    public void setCommand(String inCommand){
	    command = inCommand;
    }

    public Alertident[] getAlertidents(){
	    return alertidents;
    }

    public void setAlertidents(Alertident[] inAlertidents){
	    alertidents = inAlertidents;
    }
    /**
     * Copies arguments into corresponding fields.
     */
    public ToolAlert(Analyzer inAnalyzer, CreateTime ct, 
		     DetectTime dt, AnalyzerTime at, Source[] inSources, 
		     Target[] inTargets, Classification[] inClassifications, 
		     Assessment inAssessment, AdditionalData[] ad, String inIdent,
		     String inName, String inCommand, 
		     Alertident[] inAlertidents){

	    super(inAnalyzer, ct, dt, at, inSources, inTargets, inClassifications, 
	          inAssessment, ad, inIdent );
    	name = inName;
    	command = inCommand;
    	alertidents = inAlertidents;
    }
    /**
     * Creates an object with all fields null.
     */
    public ToolAlert(){

	this(null, null, null, null, null, null, null, null, null, null,
	     null, null, null);
    }
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public ToolAlert(Node inNode){
    	super(inNode);
    	
    	Node taNode = XMLUtils.GetNodeForName(inNode, ELEMENT_NAME);
    
    	Node nameNode =  XMLUtils.GetNodeForName(taNode, CHILD_ELEMENT_NAME);
    	if (nameNode == null) name = null;
    	else name = XMLUtils.getAssociatedString(nameNode);
    
    	Node commandNode =  XMLUtils.GetNodeForName(taNode, CHILD_ELEMENT_COMMAND);
    	if (commandNode == null) command = null;
    	else command = XMLUtils.getAssociatedString(commandNode);
    
    
    
    	NodeList children = taNode.getChildNodes();
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

    	Element toolAlertNode = parent.createElement(Alert.ELEMENT_NAME);
    	if(ident != null)
    	    toolAlertNode.setAttribute(ATTRIBUTE_IDENT, ident);
    
    	if(analyzer != null){
    	    Node analyzerNode = analyzer.convertToXML(parent);
    	    toolAlertNode.appendChild(analyzerNode);
    	}
    
    	if(createTime != null){
    	    Node createTimeNode = createTime.convertToXML(parent);
    	    toolAlertNode.appendChild(createTimeNode);
    	}
    
    	if(detectTime != null){
    	    Node detectTimeNode = detectTime.convertToXML(parent);
    	    toolAlertNode.appendChild(detectTimeNode);
    	}
    
    	if(analyzerTime != null){
    	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
    	    toolAlertNode.appendChild(analyzerTimeNode);    	    
    	}
    
    	if (sources != null){
    	    for (int i=0; i<sources.length; i++){
    		Node currentNode = sources[i].convertToXML(parent);
    		if (currentNode != null) toolAlertNode.appendChild(currentNode);
    	    }
    	}
    
    	if (targets != null){
    	    for (int i=0; i<targets.length; i++){
        		Node currentNode = targets[i].convertToXML(parent);
        		if (currentNode != null) toolAlertNode.appendChild(currentNode);
    	    }
    	}
    
    	if (classifications != null){
    	    for (int i=0; i<classifications.length; i++){    
        		Node currentNode = classifications[i].convertToXML(parent);
        		if (currentNode != null) toolAlertNode.appendChild(currentNode);
    	    }
    	}
    	if (additionalData != null){
    	    for (int i=0; i<additionalData.length; i++){
        		Node currentNode = additionalData[i].convertToXML(parent);
        		if (currentNode != null) toolAlertNode.appendChild(currentNode);
    	    }
    	}
    
    	//toolalert-specific
    	Node toolAlertSpecificNode = parent.createElement(ELEMENT_NAME);
    	toolAlertNode.appendChild(toolAlertSpecificNode);
    
    	if(name != null){
    	    Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
    	    nameNode.appendChild(parent.createTextNode(name));
    	    toolAlertSpecificNode.appendChild(nameNode);   
    	}
    
    	if(command != null){
    	    Node commandNode = parent.createElement(CHILD_ELEMENT_COMMAND);
    	    commandNode.appendChild(parent.createTextNode(command));
    	    toolAlertSpecificNode.appendChild(commandNode);
    	}
    	if (alertidents != null){
    	    for (int i=0; i<alertidents.length; i++){
        		Node currentNode = alertidents[i].convertToXML(parent);
        		if (currentNode != null) toolAlertSpecificNode.appendChild(currentNode);
    	    }
    	}
    	return toolAlertNode;
  }
}
