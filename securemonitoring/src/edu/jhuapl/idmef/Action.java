/* 
 The following passage applies to all software and text files in this distribution, 
 including this one:
 
 Copyright (c) 2002 Networks Associates Technology, Inc. under sponsorship of the 
 Defense Advanced Research Projects Agency (DARPA). 
 All Rights Reserved.

 
 Redistribution and use in source and binary forms, with or without modification, 
 are permitted provided that the following conditions are met:
 
    -> Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.

    -> Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

    -> Neither the name of the Network Associates nor the names of its 
       contributors may be used to endorse or promote products 
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
 * The Action class is used to describe any actions taken by the
 * analyzer in response to the event.  Is is represented in the XML DTD
 * as follows:
 * 
 *    &lt!ENTITY % attvals.actioncat            "
 *        ( block-installed | notification-sent | taken-offline |
 *          other )
 *    "&gt
 *    &lt!ELEMENT Action     (#PCDATA | EMPTY)* &gt
 *    &lt!ATTLIST Action
 *        category            %attvals.actioncat;     'other'
 *    &gt
 * 
 * Action has one attribute:
 * 
 * category
 *  The type of action taken.  The permitted values are shown below.
 *  The default value is "other."
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *     0    BLOCK_INSTALLED    A block of some sort was installed to
 *                             prevent an attack from reaching its
 *                             destination.  The block could be a port
 *                             block, address block, etc., or disabling
 *                             a user account.
 *     1    NOTIFICATION_SENT  A notification message of some sort was
 *                             sent out-of-band (via pager, e-mail,
 *                             etc.).  Does not include the
 *                             transmission of this alert.
 *     2    TAKEN_OFFLINE      A system, computer, or user was taken
 *                             offline, as when the computer is shut
 *          OTHER              Anything not in one of the above
 *                             categories.
 *
 * The element itself may be empty, or may contain a textual description
 * of the action, if the analyzer is able to provide additional details.
 * </pre> 
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Action implements XMLSerializable {
    
    // xml element and attribute names
    private static final String ATTRIBUTE_CATEGORY = "category";
    public static final String ELEMENT_NAME = "Action";
    
    // action categories
    public static final String BLOCK_INSTALLED = "block-installed";
    public static final String NOTIFICATION_SENT = "notification-sent";
    public static final String TAKEN_OFFLINE = "taken-offline";
    public static final String OTHER = "other";
    
    
    public Action(){
        this( null, null );
    }
    
    public Action( String category, String description ){
        if( category != null ){
            m_category = category;
        }
        m_description = description;    
    }
    
    public Action( Node node ){
        NamedNodeMap attributes = node.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_CATEGORY );
        if( attribute != null ){
            m_category = attribute.getNodeValue();
        }
        m_description = XMLUtils.getAssociatedString( node );
    }
    
    public String getCategory(){
        return m_category;
    }
    public void setCategory( String category ){
        m_category = category;   
    }
    
    public String getDescription(){
        return m_description;
    }
    public void setDescription( String description ){
        m_description = description;
    }
    
    public Node convertToXML( Document parent ){
        Element actionNode = parent.createElement( ELEMENT_NAME );  
        if( m_category != null ){
            actionNode.setAttribute( ATTRIBUTE_CATEGORY, m_category );
        }
        if( m_description != null ){
            actionNode.appendChild( parent.createTextNode( m_description ) );
        }
        return actionNode;
    }
    
    // default to other
    private String m_category = "other";
    private String m_description;
}
