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
import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** 
 * <pre>
 *  The WebService class carries additional information related to web
 *  traffic.
 *
 *  The WebService class is composed of four aggregate classes, as shown
 *  in Figure 4.19.
 *
 *               +-------------+
 *               |   Service   |
 *               +-------------+
 *                     /_\
 *                      |
 *               +-------------+
 *               | WebService  |
 *               +-------------+            +-------------+
 *               |             |<>----------|     url     |
 *               |             |            +-------------+
 *               |             |       0..1 +-------------+
 *               |             |<>----------|     cgi     |
 *               |             |            +-------------+
 *               |             |       0..1 +-------------+
 *               |             |<>----------| http-method |
 *               |             |            +-------------+
 *               |             |       0..* +-------------+
 *               |             |<>----------|     arg     |
 *               |             |            +-------------+
 *               +-------------+
 *
 *                  Figure 4.19 - The WebService Class
 *
 *  The aggregate classes that make up WebService are:
 *
 *  url
 *     Exactly one.  STRING.  The URL in the request.
 *
 *  cgi
 *     Zero or one.  STRING.  The CGI script in the request, without
 *     arguments.
 *
 *  http-method
 *     Zero or one.  STRING.  The HTTP method (PUT, GET) used in the
 *     request.
 *
 *  arg
 *     Zero or more.  STRING.  The arguments to the CGI script.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT WebService                    (
 *         url, cgi?, http-method?, arg*
 *     )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class WebService extends Service implements XMLSerializable{

    private URL url;
    private String cgi;
    private String method;
    private String args[];

    private static final String CHILD_ELEMENT_URL = "url";
    private static final String CHILD_ELEMENT_CGI = "cgi";
    private static final String CHILD_ELEMENT_METHOD = "http-method";
    private static final String CHILD_ELEMENT_ARG = "arg";
    
    public static final String ELEMENT_NAME = "WebService";
    
    public URL getUrl(){
	    return url;
    }
    public void setUrl(URL inUrl){
	    url = inUrl;
    }

    public String getCgi(){
	    return cgi;
    }

    public void setCgi(String inCgi){
	    cgi = inCgi;
    }

    public String getMethod(){
	    return method;
    }

    public void setMethod(String inMethod){
	    method = inMethod;
    }

    public String[] getArgs(){
	    return args;
    }

    public void setArgs(String[] inArgs){
	    args = inArgs;
    }

    /**Creates a new URL from the string provided. Copies other arguments into corresponding fields.
       @param inUrl the string to create the new URL object with
       
     */
    public WebService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      String inUrl, String inCgi, String inMethod, 
		      String inArgs[]){


      	super(inName, inPort, inPortlist, inProtocol, inIdent);
      	URL tempUrl;
      	try {
      	    tempUrl = new URL(inUrl);
      	} catch (MalformedURLException e) {
      	    tempUrl = null;
      	}
      	
      
      	cgi = inCgi;
      	method = inMethod;
      	args = inArgs;
    }
    
     /**Copies arguments into corresponding fields.
      */

    public WebService(String inName, Integer inPort, String inPortlist, 
		      String inProtocol, String inIdent, 

		      URL inUrl, String inCgi, String inMethod, 
		      String inArgs[]){
	
    	super(inName, inPort, inPortlist, inProtocol, inIdent);
    
    	url = inUrl;
    	cgi = inCgi;
    	method = inMethod;
    	args = inArgs;
    }

    /**Creates an object with all fields null.
     */

    public WebService() {
	    this(null, null, null, null, null, (String) null, null, null, null);
    }

    /**Creates an object from the XML Node containing the XML version of this object.
       This method will look for the appropriate tags to fill in the fields. If it cannot find
       a tag for a particular field, it will remain null.
       
    */

    public WebService (Node node) {

    	super(node);
    	
    	Node urlNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_URL);
    	if (urlNode == null) url = null;
    	else {
    	    try {
      		  url = new URL(XMLUtils.getAssociatedString(urlNode));
      	  } catch (MalformedURLException e){
      		  url = null;
    	    }
	    }

    	Node cgiNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_CGI);
    	if (cgiNode == null) cgi = null;
    	else cgi = XMLUtils.getAssociatedString(cgiNode);
    
    	Node methodNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_METHOD);
    	if (methodNode == null) method = null;
    	else method = XMLUtils.getAssociatedString(methodNode);
    
    	//get args nodes here
    	NodeList children = node.getChildNodes();
    	ArrayList argNodes = new ArrayList();
    	for (int i=0; i<children.getLength(); i++){
    	    Node finger = children.item(i);
    	    if (finger.getNodeName().equals(CHILD_ELEMENT_ARG)){
        		String newArg = XMLUtils.getAssociatedString(finger);
        		argNodes.add(newArg);
    	    }
    	}
    	args = new String[argNodes.size()];
    	for (int i=0; i< argNodes.size(); i++){
    	    args[i] = (String) argNodes.get(i);
    	}
    }


    public Node convertToXML(Document parent){
    
    	Element webserviceNode = parent.createElement(ELEMENT_NAME);
    	if(ident != null)
    	    webserviceNode.setAttribute(ATTRIBUTE_IDENT, ident);
        	
    	if(name != null){
    	    Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
    	    nameNode.appendChild(parent.createTextNode(name));
    	    webserviceNode.appendChild(nameNode);
    	    
    	}
    	if(port != null){
    	    Node portNode = parent.createElement(CHILD_ELEMENT_PORT);
    	    portNode.appendChild(parent.createTextNode(port.toString()));
    	    webserviceNode.appendChild(portNode);
    	    
    	}
    	if(portlist != null){
    	    Node portlistNode = parent.createElement(CHILD_ELEMENT_PORTLIST);
    	    portlistNode.appendChild(parent.createTextNode(portlist));
    	    webserviceNode.appendChild(portlistNode);
    	    
    	}
    	if(protocol != null){
    	    Node protocolNode = parent.createElement(CHILD_ELEMENT_PROTOCOL);
    	    protocolNode.appendChild(parent.createTextNode(protocol));
    	    webserviceNode.appendChild(protocolNode);
    	    
    	}
    
    	if(url != null){
    	    Node urlNode = parent.createElement(CHILD_ELEMENT_URL);
    	    urlNode.appendChild(parent.createTextNode(url.toString()));
    	    webserviceNode.appendChild(urlNode);
    	    
    	}else {
    	    Node urlNode = parent.createElement(CHILD_ELEMENT_URL);
    	    urlNode.appendChild(parent.createTextNode("Unknown URL"));
    	    webserviceNode.appendChild(urlNode);
    	}
    
    	if(cgi != null){
    	    Node cgiNode = parent.createElement(CHILD_ELEMENT_CGI);
    	    cgiNode.appendChild(parent.createTextNode(cgi));
    	    webserviceNode.appendChild(cgiNode);
    	    
    	}
    
    	if(method != null){
    	    Node methodNode = parent.createElement(CHILD_ELEMENT_METHOD);
    	    methodNode.appendChild(parent.createTextNode(method));
    	    webserviceNode.appendChild(methodNode);
    	    
    	}
    
    	if (args != null){
    	    for (int i=0; i<args.length; i++){
    
    		Node argNode = parent.createElement(CHILD_ELEMENT_ARG);
    		argNode.appendChild(parent.createTextNode(args[i]));
    
    		if (argNode != null) webserviceNode.appendChild(argNode);
    	    }
    	}
    
    
    	return webserviceNode;
    }
}
