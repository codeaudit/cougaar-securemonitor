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

package org.cougaar.core.security.test.monitoring.idmef;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.XMLUtils;

public class TestConfidence extends TestIdmef {
    
    public TestConfidence(){
        this( null );
    }
    public TestConfidence( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestConfidence( "TestConfidence" );
        test.run();
    }
    public Confidence createConfidence(){
        return m_msgFactory.createConfidence( Confidence.NUMERIC, new Float( 0.5f ) );
    }
    public void compare( Confidence confidence1, Confidence confidence2 ){
        if( !( confidence1.getRating().equals( confidence2.getRating() ) ) ){
            System.out.println( "Confidence category is inconsistent!" );
            System.out.println( "Confidence1.category = " + confidence1.getRating() );
            System.out.println( "Confidence2.category = " + confidence2.getRating() );
        }
        if( !( confidence1.getNumeric().equals( confidence2.getNumeric() ) ) ){
            System.out.println( "Confidence description is inconsistent!" );
            System.out.println( "Confidence1.description = " + confidence1.getNumeric() );
            System.out.println( "Confidence2.description = " + confidence2.getNumeric() );
        }
    }
    public void run(){
        Confidence confidence1 = createConfidence();
        Document document = m_docBuilder.newDocument();
        Node confidenceNode = confidence1.convertToXML( document );
        
        Confidence confidence2 = new Confidence( confidenceNode );
        compare( confidence1, confidence2 );
        document.appendChild( confidenceNode );
        XMLUtils.printDocument( document );
    }
}
