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

import java.io.FileReader;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**This class provides a set of utilities for XML*/
public class XMLUtils{

    // DOM Utilities
    /** Returns the text string which is the single child of a child of this node.
     * @param parent the node which is a parent of the single-child node.
     * @param childName the string represinting the single-child node.
     * @return the text string which is the child of the node represented by "childName" which itself is a child of parent.
    */

    public static String getSingleChildOfNode (Node parent, String childName) throws Exception{
	Node childNode =  XMLUtils.GetNodeForName(parent, childName);
        if (childNode == null) 
            throw (new Exception("Missing or incorrect" +childName+ " tag"));
	
        String childString =  XMLUtils.getAssociatedString(childNode);
	System.out.println("In getSingleChildOfNode:" +childName+ " recognized as "+childString);
        if (childString == null)
            throw (new Exception("Missing or incorrect " +childName+ " string"));
        else
	    return childString;
    }
    
    /** @param doc an XML document.
     *	@return a string representing the stringified version of that document, with minor pretty-printing.
     */

    public static String doc2String(Document doc){
	//System.out.println("XMLUtils: converting doc to string");
	StringBuffer result = new StringBuffer();
	doc2String(doc.getFirstChild(), result, 0);
	return result.toString();
    }

    /**Recursive method which has a side effect of setting the result to the pretty-printed flat text version of an XML node.
     * @param finger the current node
     * @param result the resultant string that is being built up.
     * @param indent the current indenting level.
     */

    private static void doc2String(Node finger, StringBuffer result, int indent){
	//Base Case
	for(int j=0; j<indent; j++) result.append(' ');
	if(finger.getNodeType() == Node.TEXT_NODE){
	    result.append(finger.getNodeValue().trim());
	    result.append("\n");
	    return;
	}
	result.append('<');
	//System.out.println("XMLUtils: appending " + finger.getNodeName() + " to output");
	result.append(finger.getNodeName().trim());
	result.append('>');
	result.append("\n");
        if (finger.hasChildNodes() ){
	    NodeList childList = finger.getChildNodes();
	    for(int i=0; i<childList.getLength(); i++){
		doc2String(childList.item(i), result, indent+1);
	    }
	}
	for(int j=0; j<indent; j++) result.append(' ');
	result.append("</");
	//System.out.println("XMLUtils: appending end " + finger.getNodeName() + " to output");
	result.append(finger.getNodeName().trim());
	result.append('>');
	result.append("\n");
    }



 

    /** Takes the string that corresponds to the message and returns the corresponding XML Document
    * @param xmlContentsString - the string containing the XML to parse
    * @return The parsed representation (Document)*/
    public static Document makeDocumentFromString(String xmlContentsString) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document document = null;
        try {
          DocumentBuilder builder = factory.newDocumentBuilder();
          document = builder.parse(new InputSource(new StringReader(xmlContentsString)));
        }
        catch (Exception e) {
          e.printStackTrace();
          return null;
        }
        return document;
    }

    /** Takes the parsed XML representation (i.e. Document) and a string (e.g <variable> in a <query> message)
     * @param document - the parsed XML represenation
     * @param tagName - the name of the data item whose value is desired
     * @return The string that is that value*/
    public static String GetValueForNode(Document document, String tagName) {
        NodeList nodes = document.getElementsByTagName(tagName);
        if (nodes == null)
            return (null);
        else {
            Node n = nodes.item(0);
            String value  = n.getFirstChild().getNodeValue();
            if (value == null) 
                return null;
            else 
                return value.trim();
        }
    }

    /**gets the sibling element of a node
    * @param start the node to get the sibling of
    * @return the sibling node*/
    public static Node GetNextSiblingElement(Node start) {
        if ( start == null)
          return start;
        Node node =  start.getNextSibling();
        if (node == null)
          return node;
        else if (node.getNodeType() != Node.ELEMENT_NODE)
          return GetNextSiblingElement(node);
        else
          return node;
    }

    /**Returns the node specified by name.
     * @param start the parent of the node we are looking for.
     * @param tagName the string name of the child we are looking for.*/
    public static Node GetNodeForName(Node start, String tagName) {
        // make sure we have not exhausted the possibilities
        if (start == null)
            return null;
    
        // if its not a element or a document - then it could not be what 
        //we are looking for
        if ((start.getNodeType() != Node.ELEMENT_NODE) &&  
            (start.getNodeType() != Node.DOCUMENT_NODE))
                return null;
   
        // System.out.println("In GetNodeForName - checking " 
        //+   start.getNodeName());

       // do we have a match?
        if (start.getNodeName().equals(tagName))
            return start;

       // otherwise recurse on the children - stopping at first match
        NodeList children = start.getChildNodes();
        if (children == null) 
            return null;
        else {
            for (int i=0; i<children.getLength(); i++) {
                Node toReturn = XMLUtils.GetNodeForName(children.item(i),tagName);
                if (toReturn != null)
                    return toReturn;
             }
       }

       // was not in the children either - its just not in the tree
        return null;
    }

    /**returns the type of document represented
    * @param d document to get the type of
    * @return string representing type of document*/
    static public String getDocumentType(Document d) throws Exception {
        if (d == null)
            throw new Exception();
        else 
            return(d.getDoctype().getName());
    }

    /**gets string associated with a node
    * @param node node to get string for
    * @param string associated with the input node*/
    static public String getAssociatedString(Node node) {
        // Has to be a real Node
        if (node == null)
            return null;

        // Must have one and only one string associted with it
        NodeList children = node.getChildNodes();
        if (children.getLength() > 1){
	    System.out.println("XMLUtils: Node has more than one child");
            return null;
	}
        Node firstChild = children.item(0);
	if (firstChild == null) {
	  System.out.println("XMLUtils: Node does not have a child");
	  return null;
	}
        if (firstChild.getNodeType() != Node.TEXT_NODE){
	  System.out.println("XMLUtils: Node is not a text node");
	  System.out.println("XMLUtils: Node = " + firstChild.getNodeName() + ", Parent Node = " + node.getNodeName() );
	  return null;
	}
        String stringToReturn = firstChild.getNodeValue().trim();
        if (stringToReturn.equals("")){
	    System.out.println("XMLUtils: Trimmed string is empty");
            return null;
	}
        else
            return stringToReturn;
    }
    
    /**
     * Prints the XML document to standard out
     *
     * @param document an xml document
     */
    static public void printDocument( Document document ){
        try{
            StringWriter buf = new StringWriter();

	        XMLSerializer sezr = new XMLSerializer( buf , new OutputFormat( document, "UTF-8", true) );
	        sezr.serialize( document );
	        System.out.println( "XMLUtils: printDocument()....." );
	        System.out.println( buf.getBuffer() );
	    }
	    catch( Exception e ){
	        e.printStackTrace();
	    }
    }
	

    /* Main method to test this beast */

    public static void main (String args[]){
	try {
	    while(true){
		System.out.println ("XMLUtils: Type a file to read in");
		String testFile = FileUtils.getNextLine(System.in);
		System.out.println ("XMLUtils: Opening: " +testFile);
		FileReader in = new FileReader(testFile);
		int next;
		StringBuffer fileString = new StringBuffer();
		while ((next = in.read()) != -1)
		    fileString.append((char)next);
		System.out.println ("XMLUtils: Converting " +testFile+" to XML Document");
		Document doc = makeDocumentFromString(fileString.toString());
		System.out.println ("XMLUtils: Done.");
		System.out.println ("XMLUtils: Document is of type " + getDocumentType(doc));
		System.out.println ("Converting XML Document back to string.");
		System.out.println("XMLUtils: Done. String is:\n" + doc2String(doc));
	    }
        }
        catch(Exception e) {
            e.printStackTrace();
        }
    }



    /*A few debugging routines*/

    /**prints the document tree
    * @param node node to start at
    * @param ident amount of indention*/
    public static void printTree(Node node, int ident) {
        if (node == null) 
            return;
        NodeList children;
        System.out.print("Node: " + node.getNodeName() + " ");
        switch (node.getNodeType()) {
            case Node.DOCUMENT_NODE:
              System.out.println("Document Node");
              break;
       
            case Node.ELEMENT_NODE:
              System.out.println("Element Node");
              break;
      
            case Node.TEXT_NODE:
              System.out.println("->"+node.getNodeValue().trim()+"<-");
              break;
      
            case Node.CDATA_SECTION_NODE:
              System.out.println("CData Node");
              break;
      
            case Node.PROCESSING_INSTRUCTION_NODE:
              System.out.println("Proposing Instruction Node");
               break;

            case Node.ENTITY_REFERENCE_NODE:
              System.out.println("Entity Node");
              break;

            case Node.DOCUMENT_TYPE_NODE:
              System.out.println("Document Node");
              break;
              
            default:
        }

        for (int j = 0; j<2 *ident; j++) 
            System.out.print(" ");
        System.out.println("It has the following Children");
        children = node.getChildNodes();
        if (children != null) {
            for (int i=0; i<children.getLength(); i++) {
                for (int j = 0; j<ident; j++) 
                    System.out.print(" ");
                System.out.print ("Child " + ident + "."+ i + " = ");
                printNodeType(children.item(i), ident + 1);
            }
            System.out.println();
        }
    }
	
    /**prints the type of the input node
    * @param node node to print type of
    * @param ident amount to indent*/
    public static void printNodeType(Node node, int ident) {
        System.out.print("Node: " + node.getNodeName() + " ");
        switch (node.getNodeType()) {
            case Node.DOCUMENT_NODE:
                System.out.println("Document Node");
                break;
       
            case Node.ELEMENT_NODE:
                System.out.println("Element Node");
                for (int j = 0; j<2 *ident; j++)
                    System.out.print(" ");
                System.out.println("It has the following Children");
                NodeList children = node.getChildNodes();
                if (children != null) {
                    for (int i=0; i<children.getLength(); i++) {
                        for (int j = 0; j<ident; j++)
                            System.out.print(" ");
                    System.out.print ("Child " + ident + "."+ i + " = ");
                    printNodeType(children.item(i), ident + 1);
                    }
                System.out.println();
                }
                break;
      
            case Node.TEXT_NODE:
                System.out.println("->"+node.getNodeValue().trim()+"<-");
                break;
      
            case Node.CDATA_SECTION_NODE:
                System.out.println("CData Node");
                break;
      
            case Node.PROCESSING_INSTRUCTION_NODE:
                System.out.println("Proposing Instruction Node");
                break;

            case Node.ENTITY_REFERENCE_NODE:
                System.out.println("Entity Node");
                break;

            case Node.DOCUMENT_TYPE_NODE:
                System.out.println("Document Node");
                break;
                
            default:
            }
    }
}
