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

import java.io.File;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Linkage;
import edu.jhuapl.idmef.XMLUtils;

public class TestLinkage extends TestIdmef {
    
    public TestLinkage(){
        this( null );
    }
    public TestLinkage( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestLinkage( "TestLinkage" );
        test.init();
        test.run();
    }
    public void init(){
        m_fileTester = new TestFile();
    }
    public Linkage createLinkage(){
        //createLinkage( IDMEF_File file, String category )
        return m_msgFactory.createLinkage( new File( "/home/mluu/.ssh/id_rsa.pub" ), Linkage.HARD_LINK );   
    }
    public void compare( Linkage []linkages1, Linkage []linkages2 ){
        if( linkages1.length == linkages2.length ){
            int len = linkages1.length;
            for( int i = 0; i < len; i++ ){
                compare( linkages1[ i ], linkages2[ i ] );
            }
        }
        else{
            System.out.println(" Linkage lengths NOT EQUAL!" );
            System.out.println(" Linkages1.length = " + linkages1.length );
            System.out.println(" Linkages2.length = " + linkages2.length );
        }
        
    }
    public void compare(  Linkage linkage1, Linkage linkage2 ){
        if( !( linkage1.getCategory().equals( linkage2.getCategory() ) ) ){
            System.out.println( "Linkage category is inconsistent!" );
            System.out.println( "Linkage1.category = " + linkage1.getCategory() );
            System.out.println( "Linkage2.category = " + linkage2.getCategory() );
        }
        if( linkage1.getFile() != null ){
            m_fileTester.compare( linkage1.getFile(), linkage2.getFile() );
        }
        if( !( linkage1.getName().equals( linkage2.getName() ) ) ){
            System.out.println( "Linkage name is inconsistent!" );
            System.out.println( "Linkage1.name = " + linkage1.getName() );
            System.out.println( "Linkage2.name = " + linkage2.getName() );
        }
        else if( !( linkage1.getPath().equals( linkage2.getPath() ) ) ){
            System.out.println( "Linkage path is inconsistent!" );
            System.out.println( "Linkage1.path = " + linkage1.getPath() );
            System.out.println( "Linkage2.path = " + linkage2.getPath() );
        }
    }
    public void run(){
        Linkage linkage1 = createLinkage();
        Document document = m_docBuilder.newDocument();
        //System.out.println( "converting to XML" );
        Node linkageNode = linkage1.convertToXML( document );
        //System.out.println( "instantiating Linkage from node" );
        Linkage linkage2 = new Linkage( linkageNode );
        //System.out.println( "comparing Linkage1 and Linkage2" );
        compare( linkage1, linkage2 );
        //System.out.println( "appending LinkageNode to document" );
        document.appendChild( linkageNode );
        XMLUtils.printDocument( document );
    }
    private TestFile m_fileTester;
}
