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
import org.w3c.dom.Node;

/** 
 * <pre>
 *  The OverflowAlert carries additional information related to buffer
 *  overflow attacks.  It is intended to enable an analyzer to provide
 *  the details of the overflow attack itself.
 *
 *  The OverflowAlert class is composed of three aggregate classes, as
 *  shown in Figure 4.5.
 *
 *              +------------------+
 *              |      Alert       |
 *              +------------------+
 *                      /_\
 *                       |
 *              +------------------+
 *              |  OverflowAlert   |
 *              +------------------+            +---------+
 *              |                  |<>----------| program |
 *              |                  |            +---------+
 *              |                  |       0..1 +---------+
 *              |                  |<>----------| size    |
 *              |                  |            +---------+
 *              |                  |       0..1 +---------+
 *              |                  |<>----------| buffer  |
 *              |                  |            +---------+
 *              +------------------+
 *
 *                 Figure 4.5 - The OverflowAlert Class
 *
 *  The aggregate classes that make up OverflowAlert are:
 *
 *  program
 *     Exactly one.  STRING.  The program that the overflow attack
 *     attempted to run (note: this is not the program that was
 *     attacked).
 *
 *  size
 *     Zero or one.  INTEGER.  The size, in bytes, of the overflow (i.e.,
 *     the number of bytes the attacker sent).
 *
 *  buffer
 *     Zero or one.  BYTE[].  Some or all of the overflow data itself
 *     (dependent on how much the analyzer can capture).
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT OverflowAlert                 (
 *         program, size?, buffer?
 *     )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class OverflowAlert extends Alert implements XMLSerializable{

    private String program;
    private Integer size;
    private String buffer;

    private static final String CHILD_ELEMENT_PROGRAM = "program";
    private static final String CHILD_ELEMENT_SIZE = "size";
    private static final String CHILD_ELEMENT_BUFFER = "buffer";
    
    public static final String ELEMENT_NAME = "OverflowAlert";
    
    //getters and setters

    public String getProgram(){
	    return program;
    }
    public void setProgram(String inProgram){
	    program = inProgram;
    }

    public Integer getSize(){
    	return size;
    }
    public void setSize(Integer inSize){
    	size = inSize;
    }

    public String getBuffer(){
    	return buffer;
    }
    public void setBuffer(String inBuffer){
	    buffer = inBuffer;
    }
    /**
     * Copies arguments into corresponding fields.
     */
    public OverflowAlert(Analyzer inAnalyzer, CreateTime ct, 
			 DetectTime dt, AnalyzerTime at, Source[] inSources, 
			 Target[] inTargets, Classification[] inClassifications, 
			 Assessment inAssessment, AdditionalData[] ad, String inIdent,
			 String inProgram, Integer inSize, String inBuffer){

	    super(inAnalyzer, ct, dt, at, inSources, inTargets, inClassifications, 
	      inAssessment, ad, inIdent );
        program = inProgram;
	    size = inSize;
	    buffer = inBuffer;
    }
    /**
     * Creates an object with all fields null.
     */
    public OverflowAlert(){

	    this(null, null, null, null, null, null, null, null, null,
	     null, null, null, null);
    }
    /**
     *  Creates an object from the XML Node containing the XML version of this object.
     *  This method will look for the appropriate tags to fill in the fields. If it cannot find
     *  a tag for a particular field, it will remain null.
     */
    public OverflowAlert(Node inNode){
	    super(inNode);
	    Node oaNode = XMLUtils.GetNodeForName(inNode, ELEMENT_NAME);	    
	    Node programNode =  XMLUtils.GetNodeForName(oaNode, CHILD_ELEMENT_PROGRAM);
  	  if (programNode == null) program = null;
	    else program = XMLUtils.getAssociatedString(programNode);

	    Node sizeNode =  XMLUtils.GetNodeForName(oaNode, CHILD_ELEMENT_SIZE);
	    if (sizeNode == null) size = null;
	    else size = new Integer(XMLUtils.getAssociatedString(sizeNode));

	    Node bufferNode =  XMLUtils.GetNodeForName(oaNode, CHILD_ELEMENT_BUFFER);
	    if (bufferNode == null) buffer = null;
	    else buffer = XMLUtils.getAssociatedString(bufferNode);
    }

    public Node convertToXML(Document parent){

    	Element overflowalertNode = parent.createElement(Alert.ELEMENT_NAME);
    	if(ident != null)
    	    overflowalertNode.setAttribute(ATTRIBUTE_IDENT, ident);
    	
    	if(analyzer != null){
    	    Node analyzerNode = analyzer.convertToXML(parent);
    	    overflowalertNode.appendChild(analyzerNode);
    	    
    	}
    
    	if(createTime != null){
    	    Node createTimeNode = createTime.convertToXML(parent);
    	    overflowalertNode.appendChild(createTimeNode);
    	    
    	}
    
    	if(detectTime != null){
    	    Node detectTimeNode = detectTime.convertToXML(parent);
    	    overflowalertNode.appendChild(detectTimeNode);
    	    
    	}
    
    	if(analyzerTime != null){
    	    Node analyzerTimeNode = analyzerTime.convertToXML(parent);
    	    overflowalertNode.appendChild(analyzerTimeNode);
    	    
    	}
    
    	if (sources != null){
    	    for (int i=0; i<sources.length; i++){
    		Node currentNode = sources[i].convertToXML(parent);
    		if (currentNode != null) overflowalertNode.appendChild(currentNode);
    	    }
    	}
    
    	if (targets != null){
    	    for (int i=0; i<targets.length; i++){
    		Node currentNode = targets[i].convertToXML(parent);
    		if (currentNode != null) overflowalertNode.appendChild(currentNode);
    	    }
    	}
    
    	if (classifications != null){
    	    for (int i=0; i<classifications.length; i++){    
    		Node currentNode = classifications[i].convertToXML(parent);
    		if (currentNode != null) overflowalertNode.appendChild(currentNode);
    	    }
    	}
    	if (additionalData != null){
    	    for (int i=0; i<additionalData.length; i++){
    		Node currentNode = additionalData[i].convertToXML(parent);
    		if (currentNode != null) overflowalertNode.appendChild(currentNode);
    	    }
    	}
    
    	//overflowalert-specific
    
    	Element overflowalertSpecificNode = parent.createElement(ELEMENT_NAME);
    	overflowalertNode.appendChild(overflowalertSpecificNode);
    
    	if(program != null){
    	    Node programNode = parent.createElement(CHILD_ELEMENT_PROGRAM);
    	    programNode.appendChild(parent.createTextNode(program));
    	    overflowalertSpecificNode.appendChild(programNode);
    	    
    	}
    
    	if(size != null){
    	    Node sizeNode = parent.createElement(CHILD_ELEMENT_SIZE);
    	    sizeNode.appendChild(parent.createTextNode(size.toString()));
    	    overflowalertSpecificNode.appendChild(sizeNode);
    	    
    	}
    
    	if(buffer != null){
    	    Node bufferNode = parent.createElement(CHILD_ELEMENT_BUFFER);
    	    bufferNode.appendChild(parent.createTextNode(buffer));
    	    overflowalertSpecificNode.appendChild(bufferNode);
    	    
    	}

	    return overflowalertNode;
    }
}
