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

import java.net.MalformedURLException;
import java.net.URL;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/** 
 * This class represents the name of an alert.
 *  
 * URL's are handled in this class in this manner: if the URL is valid, it is stored in the
 * url variable as a Java URL. If not, the url variable is null and the url tag will output
 * the string "Unknown URL".
 *
 * <pre>
 *  The Classification class provides the "name" of an alert, or other
 *  information allowing the manager to determine what it is (for
 *  example, to decide whether or not to display the alert on-screen,
 *  what color to display it in, etc.).
 *
 *  The Classification class is composed of two aggregate classes, as
 *  shown in Figure 4.9.
 *
 *                +----------------+
 *                | Classification |
 *                +----------------+            +------+
 *                | STRING origin  |<>----------| name |
 *                |                |            +------+
 *                |                |            +------+
 *                |                |<>----------| url  |
 *                |                |            +------+
 *                +----------------+
 *
 *                 Figure 4.9 - The Classification Class
 *
 *  The aggregate classes that make up Classification are:
 *
 *  name
 *     Exactly one.  STRING.  The name of the alert, from one of the
 *     origins listed below.
 *
 *  url
 *     Exactly one.  STRING.  A URL at which the manager (or the human
 *     operator of the manager) can find additional information about the
 *     alert.  The document pointed to by the URL may include an in-depth
 *     description of the attack, appropriate countermeasures, or other
 *     information deemed relevant by the vendor.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ENTITY % attvals.origin               "
 *         ( unknown | bugtraqid | cve | vendor-specific )
 *       "&gt
 *     &lt!ELEMENT Classification                (
 *         name, url
 *       )&gt
 *     &lt!ATTLIST Classification
 *         origin              %attvals.origin;        'unknown'
 *     &gt
 *
 *  The Classification class has one attribute:
 *
 *  origin
 *     Required.  The source from which the name of the alert originates.
 *     The permitted values for this attribute are shown below.  The
 *     default value is "unknown".
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    unknown            Origin of the name is not known
 *       1    bugtraqid          The SecurityFocus.com ("Bugtraq")
 *                               vulnerability database identifier
 *                               (http://www.securityfocus.com/vdb)
 *       2    cve                The Common Vulnerabilities and Exposures
 *                               (CVE) name (http://www.cve.mitre.org/)
 *       3    vendor-specific    A vendor-specific name (and hence, URL);
 *                               this can be used to provide product-
 *                               specific information
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 */
public class Classification implements XMLSerializable {

  private String name;
  private URL url;

  //attributes
  private String origin;
  
  // attributes and element names
  private static final String CHILD_ELEMENT_NAME = "name";
  private static final String CHILD_ELEMENT_URL = "url";
  private static final String ATTRIBUTE_ORIGIN = "origin";
  // value of url if one isn't provided 
  private static final String UNKNOWN_URL = "Unknown URL";
    
  //constants
  public static final String UNKNOWN          = "unknown";
  public static final String BUGTRAQID        = "bugtraqid";
  public static final String CVE              = "cve";
  public static final String VENDOR_SPECIFIC  = "vendor-specific";
  
  // element name
  public static final String ELEMENT_NAME = "Classification";
  
  //getters and setters
  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public URL getUrl(){
    return url;
  }
  public void setUrl(URL inUrl){
    url = inUrl;
  }

  public String getOrigin(){
    return origin;
    
  }
  public void setOrigin(String inOrigin){
    origin = inOrigin;
  }

  /**
   * Copies arguments into corresponding fields.
   */
  public Classification(String inName, URL inUrl, String inOrigin) {
    name = inName;
    url = inUrl;
    origin = inOrigin;
  }
  /**
   * Copies arguments into corresponding fields, except url. The url field is produced
   * from the passed String.
   */
  public Classification(String inName, String inUrl, String inOrigin){
    name = inName;
    try {
      url = new URL(inUrl);
    } catch (MalformedURLException e) {
      url = null;
    }
    origin = inOrigin;
  }
  /**
   * Creates an object with all fields null.
   */
  public Classification(){
    this(null, (URL) null, null);
  }
  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public Classification (Node node){

    Node nameNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NAME);
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node urlNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_URL);
    if (urlNode == null) url = null;
    else {
      try {
	      url = new URL(XMLUtils.getAssociatedString(urlNode));
      } catch (MalformedURLException e) {
	      url = null;
      }
    }

    NamedNodeMap nnm = node.getAttributes();

    Node originNode = nnm.getNamedItem(ATTRIBUTE_ORIGIN);
    if(originNode == null) origin=null;
    else origin = originNode.getNodeValue();

  }


  public Node convertToXML(Document parent){
    Element classificationNode = parent.createElement(ELEMENT_NAME);
    if(origin != null)
      classificationNode.setAttribute(ATTRIBUTE_ORIGIN, origin);

    if(name != null){
      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
      nameNode.appendChild(parent.createTextNode(name));
      classificationNode.appendChild(nameNode);
	    
    }
    Node urlNode = parent.createElement(CHILD_ELEMENT_URL);
    if(url != null){
      urlNode.appendChild(parent.createTextNode(url.toString()));
    } else {
      urlNode.appendChild(parent.createTextNode(UNKNOWN_URL));  
    }
    classificationNode.appendChild(urlNode);
    return classificationNode;
  }
  /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  Name
   *  Origin
   * <b>
   * NOTE: This is specific to how systems use IDMEF messages and
   *       what it means when two objects are equivalent.  For
   *       example, equivalence may mean a subset of the objects
   *       attributes.  It's advised that this method is modified
   *       for your particular environment.
   * </b>
   * </pre> 
   */
  public boolean equals(Object anObject) {
    boolean equal=false;
    if(anObject==null) {
      return equal;
    }
    if(anObject instanceof Classification) {
      Classification classification=(Classification)anObject;
      if((this.getOrigin().trim().equals(classification.getOrigin().trim()))
	        &&(this.getName().trim().equals(classification.getName().trim()))) {
	      equal=true;
      }
    }
    return equal;
  } 
}
