/* 
The following passage applies to all software and text files in this distribution, 
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

import java.lang.reflect.Constructor;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** 
 * <pre>
 *  The AdditionalData class is used to provide information that cannot
 *  be represented by the data model.  AdditionalData can be used to
 *  provide atomic data (integers, strings, etc.) in cases where only
 *  small amounts of additional information need to be sent; it can also
 *  be used to extend the data model and the DTD to support the
 *  transmission of complex data (such as packet headers).  Detailed
 *  instructions for extending the data model and the DTD are provided in
 *  Section 5 of the IETF IDMEF Draft.
 *  
 *  The AdditionalData element is declared in the XML DTD as follows:
 *  
 *        &lt!ENTITY % attvals.adtype               "
 *            ( boolean | byte | character | date-time | integer |
 *              ntpstamp | portlist | real | string | xml )
 *          "&gt
 *        &lt!ELEMENT AdditionalData    ANY &gt
 *        &lt!ATTLIST AdditionalData
 *           type                %attvals.adtype;        'string'
 *           meaning             CDATA                   #IMPLIED
 *        &gt
 *  
 *    The AdditionalData class has two attributes:
 *  
 *  type
 *     Required.  The type of data included in the element content.
 *     The permitted values for this attribute are shown below.  The
 *     default value is "string".
 *  
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    boolean            The element contains a boolean value,
 *                               i.e., the strings "true" or "false"
 *       1    byte               The element content is a single 8-bit
 *                               byte
 *       2    character          The element content is a single
 *                               character
 *       3    date-time          The element content is a date-time
 *                               string
 *       4    integer            The element content is an integer 
 *       5    ntpstamp           The element content is an NTP timestamp
 *       6    portlist           The element content is a list of ports
 *       7    real               The element content is a real number
 *       8    string             The element content is a string
 *       9    xml                The element content is XML-tagged data
 *
 *  meaning
 *    Optional.  A string describing the meaning of the element content.
 *    These values will be vendor/implementation dependent; the method
 *    for ensuring that managers understand the strings sent by analyzer
 *    is outside the scope of this specification.
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class AdditionalData implements XMLSerializable{

    // attributes
    private String type;
    private String meaning;
    private static final String CLASS_SUFFIX = ":class";
    private static final String ATTRIBUTE_TYPE = "type";
    private static final String ATTRIBUTE_MEANING = "meaning";
    
    // element data
    private String additionalData;
    private XMLSerializable xmlData;
    
    // element and attribute names
    public static final String ELEMENT_NAME = "AdditionalData";
   
    //constants
    public static final String BOOLEAN = "boolean";
    public static final String BYTE = "byte";
    public static final String CHARACTER = "character";
    public static final String DATE_TIME = "date-time";
    public static final String INTEGER = "integer";
    public static final String NTPSTAMP = "ntpstamp";
    public static final String PORTLIST = "portlist";
    public static final String REAL = "real";
    public static final String STRING  = "string";
    public static final String XML = "xml";

    //getters and setters
    public String getType(){
      return type;
    }
    public void setType(String inType){
      type = inType;
    }
    public String getMeaning(){
      return meaning;
    }
    public void setMeaning(String inMeaning){
      meaning = inMeaning;
    }
    public String getAdditionalData(){
      return additionalData;
    }
    public void setAdditionalData(String inAdditionalData){
      additionalData = inAdditionalData;
    }
    public XMLSerializable getXMLData(){
      return xmlData;
    }
    public void setXMLData( XMLSerializable inXMLData ){
      xmlData = inXMLData;
    }
    /**
     * Copies arguments into corresponding fields.
     */
    public AdditionalData(String inType, String inMeaning, 
        String inAdditionalData){
      type = inType;
      meaning = inMeaning;
      additionalData = inAdditionalData;
    }
    /**
     * Creates an object for an xml data type.
     *
     * @param inMeaning meaning for the additional data
     * @param inXMLData an XMLSerializable object
     */
    public AdditionalData( String inMeaning, XMLSerializable inXMLData ){
      type = XML;
      meaning = inMeaning;
      xmlData = inXMLData; 
    }
    
    /**
     * Creates an object with all fields null.
     */
    public AdditionalData(){
      this(null, null, null);
    }
    
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     *
     * If the additional data type is "xml", an additional attribute is REQUIRED for the
     * XMLSerializable object.  The attribute <ObjectName>:class=<fully qualified class> 
     * is required for the xml element inorder for the creation of the xml data using 
     * reflection.
     *
     * For example:
     * <pre>
     * &ltAdditionalData type="xml" meaning="test-data"&gt
     * &lttest:a test:class="example.Test"&gt
     *  &lttest:b&gtsome value&lt/test:b&gt
     * &lt/test:a&gt
     * </pre>
     */
    public AdditionalData (Node inNode){
      NamedNodeMap nnm = inNode.getAttributes();
      Node typeNode = nnm.getNamedItem(ATTRIBUTE_TYPE);
  
      if (typeNode != null) type = typeNode.getNodeValue();
      else type = null;

      Node meaningNode = nnm.getNamedItem(ATTRIBUTE_MEANING);
      if (meaningNode != null) meaning = meaningNode.getNodeValue();
      else meaning = null;
      
      if (type != null && type.equals(AdditionalData.XML)){
        // this is an xml data, find the element node
        NodeList nodes = inNode.getChildNodes();
        Node node = null;
        int i = 0;
        for(; i < nodes.getLength(); i++) {
          node = nodes.item(i);
          if(node.getNodeType() == Node.ELEMENT_NODE){
            break;
          }
        }
        if(i > nodes.getLength()) {
          // there are no element nodes
          additionalData = XMLUtils.getAssociatedString(inNode); 
        }
        else {
          // process the element node
          try {
            Node attr = null;
            String className = null;
            NamedNodeMap attributes = node.getAttributes();
            int size = attributes.getLength();
            for( int j = 0; i < size; i++ ){
              attr = attributes.item( j );
              if( attr.getNodeName().endsWith(CLASS_SUFFIX) ){
                // get the fully qualified class name for this xml data
                className = attr.getNodeValue();
                break;
              }
            }
            // get the Class instance for this object
            Class idmefClass = Class.forName( className );
            // construct the arguments for this class
            Class paramList[] = { Node.class };
            Object params[] = { node };
            Constructor constructor = idmefClass.getConstructor( paramList );
            // initialize the xml serializable data from the object's node
            xmlData = (XMLSerializable)constructor.newInstance( params );
          }
          catch( Exception e ) {
            e.printStackTrace();
          }
        }
      }
      else {
        additionalData = XMLUtils.getAssociatedString(inNode);
      }
    }

    public Node convertToXML(Document parent){
      Element additionalDataNode = parent.createElement(ELEMENT_NAME);
      if(type != null)
        additionalDataNode.setAttribute(ATTRIBUTE_TYPE, type);
      if(meaning != null)
        additionalDataNode.setAttribute(ATTRIBUTE_MEANING, meaning);
      if( type != null && type.equals( XML ) ){
        if( xmlData != null ) {
          additionalDataNode.appendChild( xmlData.convertToXML( parent ) );
          return additionalDataNode;
        }
      }
      if( additionalData != null ){
        additionalDataNode.appendChild( parent.createTextNode( additionalData ) );
      }
      return additionalDataNode;
    }
}
