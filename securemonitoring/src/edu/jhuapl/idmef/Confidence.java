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
 * The Confidence class is used to represent the analyzer's best
 * estimate of the validity of its analysis.  It is represented in the
 * XML DTD as follows:
 * 
 *     &lt!ENTITY % attvals.rating               "
 *         ( low | medium | high | numeric )
 *     "&gt
 *     &lt!ELEMENT Confidence (#PCDATA | EMPTY)* &gt
 *     &lt!ATTLIST Confidence
 *         rating              %attvals.rating;        'numeric'
 *     &gt
 *
 *  The Confidence class has one attribute:
 *
 *  rating
 *     The analyzer's rating of its analytical validity.  The permitted
 *     values are shown below.  The default value is "numeric."
 *
 *     Rank   Keyword            Description
 *     ----   -------            -----------
 *       0    LOW                The analyzer has little confidence in
 *                               its validity
 *       1    MEDIUM             The analyzer has average confidence in
 *                               its validity
 *       2    HIGH               The analyzer has high confidence in its
 *                               validity
 *       3    NUMERIC            The analyzer has provided a posterior
 *                               probability value indicating its
 *                               confidence in its validity
 *
 *  This element should be used only when the analyzer can produce
 *  meaningful information.  Systems that can output only a rough
 *  heuristic should use "low", "medium", or "high" as the rating value.
 *  In this case, the element content should be omitted.
 *
 *  Systems capable of producing reasonable probability estimates should
 *  use "numeric" as the rating value and include a numeric confidence
 *  value in the element content. This numeric value should reflect a
 *  posterior probability (the probability that an attack has occurred
 *  given the data seen by the detection system and the model used by the
 *  system). It is a floating point number between 0.0 and 1.0,
 *  inclusive. The number of digits should be limited to those
 *  representable by a single precision floating point value, and may be
 *  represented as described in Section 4.4.2.
 * <b>
 *  NOTE: It should be noted that different types of analyzers may
 *        compute confidence values in different ways and that in many
 *        cases, confidence values from different analyzers should not be
 *        compared (for example, if the analyzers use different methods
 *        of computing or representing confidence, or are of different
 *        types or configurations).  Care should be taken when
 *        implementing systems that process confidence values (such as
 *        event correlators) not to make comparisons or assumptions that
 *        cannot be supported by the system's knowledge of the
 *        environment in which it is working.
 * </b>
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 * @since IDMEF Specification Draft v0.6
 */
public class Confidence implements XMLSerializable {
    
    // xml element and attribute names
    private static final String ATTRIBUTE_RATING = "rating";
    public static final String ELEMENT_NAME = "Confidence";
    
    // rating
    public static final String LOW = "low";
    public static final String MEDIUM = "medium";
    public static final String HIGH = "high";
    public static final String NUMERIC = "numeric";
    
    public Confidence(){
        this( null, null );
    }
    
    public Confidence( String rating, Float numeric ){
        m_rating = rating;
        m_numeric = numeric;
    }
    
    public Confidence( Node node ){
        NamedNodeMap attributes = node.getAttributes();
        
        Node attribute = attributes.getNamedItem( ATTRIBUTE_RATING );
        if( attribute != null ){
            m_rating = attribute.getNodeValue();
        }
        if( m_rating.equals( NUMERIC ) ){
           try {
                String numeric = XMLUtils.getAssociatedString( node );
                if( numeric != null ){
                    m_numeric = new Float( numeric );
                }
            }
            catch( NumberFormatException nfe ){
                // do we care?
                nfe.printStackTrace();  
            }
        }
    }
    
    public String getRating(){
        return m_rating;
    }
    public void setRating( String rating ){
        m_rating = rating;
    }
    
    public Float getNumeric(){
        return m_numeric;
    }
    public void setNumeric( Float numeric ){
        m_numeric = numeric;
    }
    
    public Node convertToXML( Document parent ){
        Element confidenceNode = parent.createElement( ELEMENT_NAME );  
        if( m_rating != null ){
            confidenceNode.setAttribute( ATTRIBUTE_RATING, m_rating );
        }
        if( m_rating.equals( NUMERIC ) &&
            ( m_numeric != null ) ){
            // set the Confidence node value iff rating is NUMERIC
            confidenceNode.appendChild( parent.createTextNode( m_numeric.toString() ) );   
        } 
        return confidenceNode;  
    }   
    // numeric is the default
    private String m_rating = NUMERIC;
    private Float m_numeric;
}
