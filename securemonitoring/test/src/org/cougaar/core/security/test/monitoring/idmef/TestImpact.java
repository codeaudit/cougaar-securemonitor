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

import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.XMLUtils;

public class TestImpact extends TestIdmef {
    
    public TestImpact(){
        this( null );
    }
    public TestImpact( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestImpact( "TestImpact" );
        test.run();
    }
    public Impact createImpact(){
        return m_msgFactory.createImpact( Impact.HIGH, 
                                          Impact.SUCCEEDED, 
                                          Impact.DOS,
                                          "test dos attack" );    
    }
    public void compare( Impact impact1, Impact impact2 ){
        if( !( impact1.getSeverity().equals( impact2.getSeverity() ) ) ){
            System.out.println( "Impact severity is inconsistent!" );
            System.out.println( "Impact1.severity = " + impact1.getSeverity() );
            System.out.println( "Impact2.severity = " + impact2.getSeverity() );
        }
        if( !( impact1.getCompletion().equals( impact2.getCompletion() ) ) ){
            System.out.println( "Impact completion is inconsistent!" );
            System.out.println( "Impact1.completion = " + impact1.getCompletion() );
            System.out.println( "Impact2.completion = " + impact2.getCompletion() );
        }
        if( !( impact1.getType().equals( impact2.getType() ) ) ){
            System.out.println( "Impact type is inconsistent!" );
            System.out.println( "Impact1.type = " + impact1.getType() );
            System.out.println( "Impact2.type = " + impact2.getType() );
        }
        if( !( impact1.getDescription().equals( impact2.getDescription() ) ) ){
            System.out.println( "Impact description is inconsistent!" );
            System.out.println( "Impact1.description = " + impact1.getDescription() );
            System.out.println( "Impact2.description = " + impact2.getDescription() );
        }
    }
    public void run(){
        Impact impact1 = createImpact();
        Document document = m_docBuilder.newDocument();
        Node impactNode = impact1.convertToXML( document );
        
        Impact impact2 = new Impact( impactNode );
        compare( impact1, impact2 );
        document.appendChild( impactNode );
        XMLUtils.printDocument( document );
    }
}
