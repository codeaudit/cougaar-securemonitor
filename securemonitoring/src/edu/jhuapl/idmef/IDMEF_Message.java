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

import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xerces.parsers.DOMParser;
import org.apache.xml.serialize.OutputFormat;
import org.apache.xml.serialize.XMLSerializer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * <pre>
 * 
 *  All IDMEF messages are instances of the IDMEF_Message class; it is
 *  the top-level class of the IDMEF data model, as well as the IDMEF
 *  DTD.  There are currently two types (subclasses) of IDMEF-Message:
 *  Alert and Heartbeat.
 *
 *  Because DTDs do not support subclassing (see Section 3.3.4 of the IDMEF
 *  specification draft v0.7), the inheritance relationship between 
 *  IDMEF-Message and the Alert and Heartbeat subclasses shown in Figure 4.1
 *  has been replaced with an aggregate relationship.  This is declared in 
 *  the IDMEF DTD as follows:
 *
 *     &lt!ENTITY % attlist.idmef                "
 *         version             CDATA                   #FIXED    '1.0'
 *      "&gt
 *     &lt!ELEMENT IDMEF-Message                 (
 *         (Alert | Heartbeat)*
 *      )&gt
 *     &lt!ATTLIST IDMEF-Message
 *         %attlist.idmef;
 *     &gt
 *
 *  The IDMEF_Message class has a single attribute:
 *
 *  version
 *     The version of the IDMEF-Message specification this message conforms to.  
 *     Applications specifying a value for this attribute MUST specify the value 
 *     "1.0".
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */

public abstract class IDMEF_Message implements XMLSerializable {

    public static final String ELEMENT_NAME = "IDMEF-Message";
    public static final String ATTRIBUTE_VERSION = "version";
    
    /**The current implemented version of IDMEF*/
    protected static String version = "1.0";

    /**The current location of the idmef DTD File*/
    protected static String dtdFileLocation = null;
    protected static String entityDtdFileLocation = null;
    
    private static String PUBLIC_ID = "-//IETF//DTD RFC XXXX IDMEF v1.0//EN";

   
    //getters and setters
    public static void setVersion (String vers){
	    version = vers;
    }

    public static String getVersion (){
	    return version;
    }

    public static String getDtdFileLocation(){
	    return dtdFileLocation;
    }
    public static void setDtdFileLocation(String inDtdFileLocation){
	    dtdFileLocation = inDtdFileLocation ;
    }
    public static String getEntityDtdFileLocation(){
	    return entityDtdFileLocation;
    }
    public static void setEntityDtdFileLocation(String inEntityDtdFileLocation){
	    entityDtdFileLocation = inEntityDtdFileLocation ;
    }

    public Node convertToXML(Document parent){
	    Element idmefNode = parent.createElement(ELEMENT_NAME);
	    if(version != null)
	      idmefNode.setAttribute(ATTRIBUTE_VERSION, version);
	    return idmefNode;
    }

    /**
     * This method is used to create messages from input XML Strings. This
     * method really only parses the String and calls the createMessage(Document) method.
     * @see #createMessage(Document inputXML)
     * @param inputXML the String to turn into a message.
     * @return the Message that is created from the String.
     */
    public static IDMEF_Message createMessage(String inputXML){
	    try{
	      DOMParser parser = new DOMParser();
              /*
              parser.setEntityResolver(new EntityResolver() {
                  public InputSource resolveEntity(String publicId, String systemId) { return null; }
                });
              */
	      parser.parse(new InputSource(new StringReader(inputXML)));
	      Document newMessage = parser.getDocument();
  	    return createMessage(newMessage);
	     } 
	     catch(Exception e){ 
	        e.printStackTrace();
	     }
	     return null;
    }
    /**
     * This method is used to create messages from input XML Documents.
     * @param inputXML the Document to turn into a message.
     * @return the Message that is created from the String.
     */
    public static IDMEF_Message createMessage(Document inputXML){
	    Element root = inputXML.getDocumentElement();
	
	    NodeList children = root.getChildNodes();
	    IDMEF_Message returnValue = null;
	    for (int i=0; i<children.getLength();i++){
	      if(children.item(i).getNodeName().equals(Alert.ELEMENT_NAME)){
		      boolean isAlertSubclass = false;
		      //System.out.println("This is an alert");
		      NodeList alertChildren = children.item(i).getChildNodes();
		      for (int j=0; j<alertChildren.getLength();j++){
  		      if (alertChildren.item(j).getNodeName().equals(CorrelationAlert.ELEMENT_NAME)){
			        //System.out.println("This is a CorrelationAlert");
			        returnValue =  new CorrelationAlert(children.item(i));
			        isAlertSubclass = true;
		        }
		        if (alertChildren.item(j).getNodeName().equals(ToolAlert.ELEMENT_NAME)){
  			      //System.out.println("This is a ToolAlert");
			        returnValue =  new ToolAlert(children.item(i));
			        isAlertSubclass = true;
		        }
		        if (alertChildren.item(j).getNodeName().equals(OverflowAlert.ELEMENT_NAME)){
  			      //System.out.println("This is a OverflowAlert");
			        returnValue =  new OverflowAlert(children.item(i));
			        isAlertSubclass = true;
		        }
		      }
		      if (!isAlertSubclass){
  		      returnValue =  new Alert(children.item(i));
		      }
	      }
	      else if(children.item(i).getNodeName().equals("Heartbeat")){
  		    //System.out.println("This is a Heartbeat");
		      returnValue = new Heartbeat (children.item(i));
	      }
	    }
	    //System.out.println("This is the document I created:");
	    //if (returnValue != null) System.out.println(returnValue.serialize());
	
	    return returnValue;
    }

    /**
     * This method converts this message to a pretty-printed XML string.
     */
    public String toString(){
	    try{
	      Document document = toXML(); 
  	    StringWriter buf=new StringWriter(2048);
	      OutputFormat of = new OutputFormat(document, "UTF-8", true);
             
	      if(getDtdFileLocation() != null) {
	        of.setDoctype(null, getDtdFileLocation());
              }
              else {
	        of.setDoctype(PUBLIC_ID, null);
	      } 
	      //of.getOmitDocumentType();
	      XMLSerializer sezr = new XMLSerializer (buf , of);
	          /*  
              if(getEntityDtdFileLocation() != null) {
                sezr.externalEntityDecl("x-cougaar", null, getEntityDtdFileLocation());
              }
             */ 
	      sezr.serialize(document);
	     
	      return buf.toString();
	    }
	    catch (Exception e){
	      return null;
	    }
    }
   
    public Document toXML() throws ParserConfigurationException{
	    Document document = newDocument(); 
	    Element root = document.createElement(ELEMENT_NAME); 
	    document.appendChild (root);
	    if(version != null){
        root.setAttribute(ATTRIBUTE_VERSION, version );
	    }
	
	    Node messageNode = this.convertToXML(document);
	    root.appendChild(messageNode);
	    return document;
    }
   
    public static Document newDocument() throws ParserConfigurationException {
      if(builder == null) {
        synchronized(factory) {
          if(builder == null) {
            builder = factory.newDocumentBuilder();
          }
        }
      }
      
      synchronized(builder) {
        return builder.newDocument();
      }
    }
    private static DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    private static DocumentBuilder builder = null;
}

