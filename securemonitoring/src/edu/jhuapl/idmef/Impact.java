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
 * The Impact class is used to provide the analyzer's assessment of the
 * impact of the event on the target(s).  It is represented in the XML
 *  DTD as follows:
 *
 *     &lt!ENTITY % attvals.severity             "
 *         ( low | medium | high )
 *     "&gt
 *     &lt!ENTITY % attvals.completion           "
 *         ( failed | succeeded )
 *     "&gt
 *     &lt!ENTITY % attvals.impacttype           "
 *         ( admin | dos | file | recon | user | other )
 *     "&gt
 *     &lt!ELEMENT Impact     (#PCDATA | EMPTY)* &gt
 *     &lt!ATTLIST Impact
 *         severity            %attvals.severity;      #IMPLIED
 *         completion          %attvals.completion;    #IMPLIED
 *         type                %attvals.impacttype;    'other'
 *     &gt
 *
 * The Impact class has three attributes:
 *
 * severity
 *    An estimate of the relative severity of the event.  The permitted
 *    values are shown below.  There is no default value.
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    low                Low severity
 *      1    medium             Medium severity
 *      2    high               High severity
 *
 * completion
 *    An indication of whether the analyzer believes the attempt that
 *    the event describes was successful or not.  The permitted values
 *    are shown below.  There is no default value.
 *
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    failed             The attempt was not successful
 *      1    succeeded          The attempt succeeded
 *
 * type
 *    The type of attempt represented by this event, in relatively broad
 *    categories.  The permitted values are shown below.  The default
 *    value is "other."
 * 
 *    Rank   Keyword            Description
 *    ----   -------            -----------
 *      0    admin              Administrative privileges were
 *                              attempted or obtained
 *      1    dos                A denial of service was attempted or
 *                              completed
 *      2    file               An action on a file was attempted or
 *                              completed
 *      3    recon              A reconnaissance probe was attempted
 *                              or completed
 *      4    user               User privileges were attempted or
 *                              obtained
 *      5    other              Anything not in one of the above
 *                              categories
 *
 * All three attributes are optional.  The element itself may be empty,
 * or may contain a textual description of the impact, if the analyzer
 * is able to provide additional details.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class Impact implements XMLSerializable {
   
    private static final String ATTRIBUTE_SEVERITY = "severity";
    private static final String ATTRIBUTE_COMPLETION = "completion";
    private static final String ATTRIBUTE_TYPE = "type";
     
    public static final String ELEMENT_NAME = "Impact";
   
    // severity
    public static final String LOW = "low";
    public static final String MEDIUM = "medium";
    public static final String HIGH = "high";
    
    // completion
    public static final String FAILED = "failed";
    public static final String SUCCEEDED = "succeeded";
    
    // type
    public static final String ADMIN = "admin";
    public static final String DOS = "dos";
    public static final String FILE = "file";
    public static final String USER = "user";
    public static final String OTHER = "other";
    
    public Impact(){
        this( null, null, null, null );
    }
    
    public Impact( String severity, 
                   String completion, 
                   String type,
                   String description ){
        m_severity = severity;
        m_completion = completion;
        m_type = type;
        m_description = description;
    }
    
    public Impact( Node node ){
        NamedNodeMap attributes = node.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_SEVERITY );
        if( attribute != null ){
            m_severity = attribute.getNodeValue();
        }
        attribute = attributes.getNamedItem( ATTRIBUTE_COMPLETION );
        if( attribute != null ){
            m_completion = attribute.getNodeValue();
        }
        attribute = attributes.getNamedItem( ATTRIBUTE_TYPE );
        if( attribute != null ){
            m_type = attribute.getNodeValue();
        }
        m_description = XMLUtils.getAssociatedString( node );
    }
    
    public String getSeverity(){
        return m_severity;
    }
    public void setSeverity( String severity ){
        m_severity = severity;
    }
    
    public String getCompletion(){
        return m_completion;
    }
    public void setCompletion( String completion ){
        m_completion = completion;
    }
    
    public String getType(){
        return m_type;
    }
    public void setType( String type ){
        m_type = type;
    }
    
    public String getDescription(){
        return m_description;
    }
    public void setDesciption( String description ){
        m_description = description;
    }
            
    public Node convertToXML( Document parent ){
        Element impactNode = parent.createElement( ELEMENT_NAME );  
        if( m_severity != null ){
            impactNode.setAttribute( ATTRIBUTE_SEVERITY, m_severity );
        }
        if( m_completion != null ){
            impactNode.setAttribute( ATTRIBUTE_COMPLETION, m_completion );
        }
        if( m_type != null ){
            impactNode.setAttribute( ATTRIBUTE_TYPE, m_type );
        }
        if( m_description != null ){
            impactNode.appendChild( parent.createTextNode( m_description ) );
        }
        
        return impactNode; 
    }
    
    private String m_severity;
    private String m_completion;
    private String m_type;
    private String m_description;
}
