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

import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * <pre>
 *  The Assessment class is used to provide the analyzer's assessment of
 *  an event -- its impact, actions taken in response, and confidence.
 *
 *  The Assessment class is composed of three aggregate classes, as shown
 *  in Figure below.
 *  
 *              +------------------+
 *              |   Assessment     |
 *              +------------------+       0..1 +------------+
 *              |                  |<>----------|   Impact   |
 *              |                  |            +------------+
 *              |                  |       0..* +------------+
 *              |                  |<>----------|   Action   |
 *              |                  |            +------------+
 *              |                  |       0..1 +------------+
 *              |                  |<>----------| Confidence |
 *              |                  |            +------------+
 *              +------------------+
 *  
 *  The aggregate classes that make up Assessment are:
 *
 *  Impact
 *      Zero or one.  The analyzer's assessment of the impact of the event
 *      on the target(s).
 *
 *  Action
 *      Zero or more.  The action(s) taken by the analyzer in response to
 *      the event.
 *
 *  Confidence
 *      A measurement of the confidence the analyzer has in its evaluation
 *      of the event.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Assessment                    (
 *         Impact?, Action*, Confidence?
 *       )&gt
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 * @since IDMEF Specification Draft v0.6
 */
public class Assessment implements XMLSerializable {
    
    public static final String ELEMENT_NAME = "Assessment";
    
    public Assessment( Impact impact, Action []actions, Confidence confidence ){
        m_impact = impact;
        m_actions = actions;
        m_confidence = confidence;
    }
    
    public Assessment( Node node ){
	    NodeList childList = node.getChildNodes();
	    ArrayList actionList = new ArrayList();
	    int len = childList.getLength();
    	
    	for ( int i = 0; i < len; i++ ){
    	    Node childNode = childList.item( i );
    	    String nodeName = childNode.getNodeName();
    	    if( m_impact == null && nodeName.equals( Impact.ELEMENT_NAME ) ){
         		// there should be one impact element
         		m_impact = new Impact( childNode );
	        }
	        else if( nodeName.equals( Action.ELEMENT_NAME ) ){
	            // there could be more than one action element
	            actionList.add( new Action( childNode ) );
	        }
	        else if( m_confidence == null && 
	                 nodeName.equals( Confidence.ELEMENT_NAME ) ){
	            // there should be one confidence element
	            m_confidence = new Confidence( childNode );	            
	        }
	    }
	    int size = actionList.size();
	    if( size > 0 ){ 
	        m_actions = new Action[ size ];
	        for( int i = 0; i < size; i++ ){
	            m_actions[ i ] = ( Action )actionList.get( i );
            }
        }
    }
    
    public Impact getImpact(){
        return m_impact;
    }
    public void setImpact( Impact impact ){
        m_impact = impact;
    }
    
    public Action []getActions(){
        return m_actions;
    }
    public void setActions( Action []actions ){
        m_actions = actions;
    }
    
    public Confidence getConfidence(){
        return m_confidence;
    }
    public void setConfidence( Confidence confidence ){
        m_confidence = confidence;
    }
    
    public Node convertToXML( Document parent ) {
        Element assessmentNode = parent.createElement( ELEMENT_NAME );
        if( m_impact != null ){
            assessmentNode.appendChild( m_impact.convertToXML( parent ) );
        }
        if( m_actions != null ){
            int len = m_actions.length;
            for( int i = 0; i < len; i++ ){
                assessmentNode.appendChild( m_actions[ i ].convertToXML( parent ) );
            }
        }
        if( m_confidence != null ){
            assessmentNode.appendChild( m_confidence.convertToXML( parent ) );
        }
        return assessmentNode;
    }
 
    private Impact m_impact;
    private Action m_actions[];
    private Confidence m_confidence;
}
