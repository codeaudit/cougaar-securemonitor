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
 * Alert identifiers are only unique across the alerts sent by a single analyzer, 
 * the optional "analyzerid" attribute of "alertident" should be used to identify
 * the analyzer that a particular alert came from.  If the "analyzerid" is not 
 * provided, the alert is assumed to have come from the same analyzer that is 
 * sending the ToolAlert.
 *
 * This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT ToolAlert                     (
 *         name, command?, alertident+
 *       )&gt
 *     &lt!ELEMENT alertident          (#PCDATA) &gt
 *     &lt!ATTLIST alertident
 *         analyzerid          CDATA                   #IMPLIED
 *     &gt
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 */
public class Alertident implements XMLSerializable{
  //attributes
  private String analyzerid;
    
  //element data
  private String elementData;
  
  // element and attribute names
  private static final String ATTRIBUTE_ANALYZERID = "analyzerid";
  public static final String ELEMENT_NAME = "alertident";
  
  //getters and setters
  public String getAnalyzerid(){
	  return analyzerid;
  }

  public String getElementData(){
	  return elementData;
  }
  public void setAnalyzerId(String inAnalyzerid){
	  analyzerid = inAnalyzerid;
  }
  public void setElementData(String inAlertident){
	  elementData = inAlertident;
  }
  
  /**
   * Copies arguments into corresponding fields.
   */
  public Alertident(String inAnalyzerid, String inAlertident){
	  analyzerid = inAnalyzerid;
	  elementData = inAlertident;
  }
  /**
   * Creates an object with all fields null.
   */
  public Alertident(){
	  this(null, null);
  }
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public Alertident (Node node){
	  elementData = XMLUtils.getAssociatedString(node);
	  NamedNodeMap nnm = node.getAttributes();
	  Node aidNode = nnm.getNamedItem(ATTRIBUTE_ANALYZERID);
	  if (aidNode != null)
	    analyzerid = aidNode.getNodeValue();
  }

  public Node convertToXML(Document parent){
  	Element alertidentNode = parent.createElement(ELEMENT_NAME);
	  if (analyzerid != null)
	    alertidentNode.setAttribute(ATTRIBUTE_ANALYZERID, analyzerid);

	  alertidentNode.appendChild(parent.createTextNode(elementData));
	  return alertidentNode;
  }
}
