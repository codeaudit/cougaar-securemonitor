/* 
 * <copyright> 
 *  Copyright 1999-2004 Cougaar Software, Inc.
 *  under sponsorship of the Defense Advanced Research Projects 
 *  Agency (DARPA). 
 *  
 *  You can redistribute this software and/or modify it under the
 *  terms of the Cougaar Open Source License as published on the
 *  Cougaar Open Source Website (www.cougaar.org).  
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *  
 * </copyright> 
 */ 

package org.cougaar.core.security.monitoring.idmef;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.XMLSerializable;
import edu.jhuapl.idmef.XMLUtils;

/**
 * <pre>
 * Agent class represents a Cougaar Agent.  Agent information is specified in
 * AdditionalData that references a Source or Target of an event.
 * 
 *            +---------------------+
 *            |        Agent        |
 *            +---------------------+
 *            | STRING name         |
 *            |                     | 0..1       +---------------+
 *            |                     |<>----------|  description  |
 *            |                     |            +---------------+
 *            |                     | 0..1       +-----------+
 *            |                     |<>----------|  location |
 *            |                     |            +-----------+
 *            |                     | 0..1       +-----------+
 *            |                     |<>----------|  Address  |
 *            |                     |            +-----------+
 *            |                     | 1..n       +-------------+
 *            |                     |<>----------|  ref-ident  |
 *            |                     |            +-------------+
 *            +---------------------+ 
 *
 *
 *  &lt!ELEMENT Cougaar:Agent (
 *   Cougaar:description?, 
 *   Cougaar:location?,
 *   Address?, 
 *   Cougaar:ref-ident+ ) &gt
 *
 *  &lt!ATTLIST Cougaar:Agent
 *      xmlns                   CDATA   #FIXED
 *          'idmef+cougaar'
 *      xmlns:Cougaar           CDATA   #FIXED
 *          'idmef+cougaar'
 *      Cougaar:name            CDATA   #REQUIRED 
 *      Cougaar:class           CDATA   #FIXED  
 *          'org.cougaar.core.security.monitoring.idmef.Agent' &gt
 *
 *  &lt!ELEMENT Cougaar:description   (#PCDATA) &gt
 *  &lt!ELEMENT Cougaar:location      (#PCDATA) &gt
 *  &lt!ELEMENT Cougaar:ref-ident     (#PCDATA) &gt
 *
 * </pre>
 * @since IDMEF Message v1.0
 */
public class Agent implements XMLSerializable, Cloneable {
    
    public final static String COUGAAR_NAMESPACE = "idmef+cougaar";
    public final static String COUGAAR_NAMESPACE_PREFIX = "Cougaar:";
    public final static String ELEMENT_NAME = COUGAAR_NAMESPACE_PREFIX + "Agent";
    public final static String NAME_ATTRIBUTE = COUGAAR_NAMESPACE_PREFIX + "name";
    public final static String CLASS_ATTRIBUTE = COUGAAR_NAMESPACE_PREFIX + "class";
    public final static String DESCRIPTION_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "desciption";
    public final static String LOCATION_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "location";
    public final static String REF_IDENT_ELEMENT = COUGAAR_NAMESPACE_PREFIX + "ref-ident";
    
    /**
     * The meaning of an AdditionalData describing an agent
     */
    public final static String AGENT_INFO_MEANING = "AGENT_INFO";
    /**
     * The meaning of an AdditionalData describing the agent that references a source
     */
    public final static String SOURCE_MEANING = "SOURCE_AGENT";
    /**
     * The meaning of an AdditionalData describing the agent that references a target
     */
    public final static String TARGET_MEANING = "TARGET_AGENT";
    
    public Agent()
    {
        this( null, null, null, null, null );
    }
  
    public Agent( String name, String description, 
                  String location, Address address, 
                  String []refIdents ){
        m_name = name;
        m_description = description;
        m_location = location;
        m_address = address;
        m_refIdents = refIdents;
    }

    public Agent( Node agentNode ){
        // set the private member variables accordingly
      
      NodeList children = agentNode.getChildNodes();
    	List refIdents = new ArrayList();
      int len = children.getLength();
    	for( int i = 0; i < len; i++ ){
    	    Node child = children.item( i );
    	    String nodeName = child.getNodeName();
    	    if( ( m_description == null ) && 
    	        nodeName.equals( DESCRIPTION_ELEMENT ) ){
        		m_description = XMLUtils.getAssociatedString( child );
	        }
	        else if( ( m_location == null ) && 
    	        nodeName.equals( LOCATION_ELEMENT ) ){
        		m_location = XMLUtils.getAssociatedString( child );
	        }
	        else if( nodeName.equals( Address.ELEMENT_NAME ) ){
	            m_address = new Address( child );
	        }
	        else if( nodeName.equals( REF_IDENT_ELEMENT ) ){
                refIdents.add( XMLUtils.getAssociatedString( child ) );
    	    }
	    }
        
      int size = refIdents.size();
      if( size > 0 ){
        m_refIdents = new String[ size ];
        for( int i = 0; i < size; i++ ){
          m_refIdents[ i ] = ( String ) refIdents.get( i );
        }
      }
     
    	NamedNodeMap nnm = agentNode.getAttributes();

    	Node nameNode = nnm.getNamedItem( NAME_ATTRIBUTE );
    	if( nameNode != null) {
    	    m_name = nameNode.getNodeValue();
        }
      // we can safely ignore the class attribute
    }
    
    public String getName(){
        return m_name;
    }
    public void setName( String name ){
        m_name = name;
    }
        
    public String getDescription(){
        return m_description;
    }
    public void setDescription( String description ){
        m_description = description;
    }
    
    public String getLocation(){
        return m_location;
    }
    public void setLocation( String location ){
        m_location = location;
    }
    
    public Address getAddress(){
        return m_address;
    }
    public void setAddress( Address address ){
        m_address = address;
    }

    public String []getRefIdents()
    {
        return m_refIdents;
    }
    public void setRefIdents( String []refIdents )
    {
        m_refIdents = refIdents;
    }
    
    /**
     *   Convert Agent to an XML node.
     *   <br>
     *   Example Agent node:
     *   <pre>
     *   &ltCougaar:Agent Cougaar:name="ViewRecordAgent" Cougaar:class="org.cougaar.core.security.monitoring.idmef.Agent"&gt
     *      &ltCougaar:description&gtAgent used to view confidential records&lt/Cougaar:description&gt
     *      &ltCougaar:location>Santa Clara, CA&lt/Cougaar:location&gt
     *      &ltAddress category="url"&gt
     *          &ltaddress&gtrmi://myhost.com:2121/ViewRecordAgent&lt/address&gt
     *      &lt/Address&gt
     *      &ltCougaar:ref-ident>a1b2c3d4&lt/Cougaar:ref-ident&gt
     *   &lt/Cougaar:Agent&gt
     *  </pre>
     */
    public Node convertToXML( Document parent )
    {
        
      Element agentNode = parent.createElement( ELEMENT_NAME );
        
      if( m_name != null ){
        agentNode.setAttribute( NAME_ATTRIBUTE, m_name );
	    }
	    agentNode.setAttribute( CLASS_ATTRIBUTE, getClass().getName() );
	    if( m_description != null ) {
            Node descriptionElm = parent.createElement( DESCRIPTION_ELEMENT );
	        descriptionElm.appendChild( parent.createTextNode( m_description ) );
	        agentNode.appendChild( descriptionElm );
	    }
	    if( m_location != null ) {
	        Node locationElm = parent.createElement( LOCATION_ELEMENT );
	        locationElm.appendChild( parent.createTextNode( m_location ) );
	        agentNode.appendChild( locationElm );
	    }
	    if( m_address != null ) {
	        agentNode.appendChild( m_address.convertToXML( parent ) );    
	    }
        if( m_refIdents != null && m_refIdents.length > 0 ) {
	        int len = m_refIdents.length;
	        for( int i = 0; i < len; i++ ) {
	            Node refIdentNode = parent.createElement( REF_IDENT_ELEMENT );
	            refIdentNode.appendChild( parent.createTextNode( m_refIdents[ i ] ) );
	            agentNode.appendChild( refIdentNode );
	        }
	    }
	    return agentNode;
    }
   
    public Object clone(){
      try{
        return super.clone();
      }
      catch (CloneNotSupportedException e) { 
	      // this shouldn't happen, since we are Cloneable
	      throw new InternalError();
	    }
    }
    
    private String m_name;
    private String m_description;
    private String m_location;
    private Address m_address;
    private String m_refIdents[];
}
