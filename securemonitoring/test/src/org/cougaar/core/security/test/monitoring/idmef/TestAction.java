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

import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.XMLUtils;

public class TestAction extends TestIdmef {
    
    public TestAction(){
        this( null );
    }
    public TestAction( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestAction( "TestAction" );
        test.run();
    }
    
    public Action createAction(){
        return m_msgFactory.createAction( null, "this is a test action" );   
    }
    public void compare( Action []actions1, Action []actions2 ){
        if( actions1.length == actions2.length ){
            int len = actions1.length;
            for( int i = 0; i < len; i++ ){
                compare( actions1[ i ], actions2[ i ] );
            }
        }
        else{
            System.out.println(" Actions lengths NOT EQUAL!" );
            System.out.println(" Actions1.length = " + actions1.length );
            System.out.println(" Actions2.length = " + actions2.length );
        }
        
    }
    public void compare( Action action1, Action action2 ){
        if( !( action1.getCategory().equals( action2.getCategory() ) ) ){
            System.out.println( "Action category is inconsistent!" );
            System.out.println( "Action1.category = " + action1.getCategory() );
            System.out.println( "Action2.category = " + action2.getCategory() );
        }
        if( !( action1.getDescription().equals( action2.getDescription() ) ) ){
            System.out.println( "Action description is inconsistent!" );
            System.out.println( "Action1.description = " + action1.getDescription() );
            System.out.println( "Action2.description = " + action2.getDescription() );
        }    
    }
    public void run(){
        Action action1 = createAction();
        Document document = m_docBuilder.newDocument();
        Node actionNode = action1.convertToXML( document );
        
        Action action2 = new Action( actionNode );
        compare( action1, action2 );
        document.appendChild( actionNode );
        XMLUtils.printDocument( document );
    }
}
