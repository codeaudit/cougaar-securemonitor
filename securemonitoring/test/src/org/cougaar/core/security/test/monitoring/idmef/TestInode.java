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

import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Inode;
import edu.jhuapl.idmef.XMLUtils;

public class TestInode extends TestIdmef {

    public TestInode(){
        this( null );
    }
    public TestInode( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestInode( "TestInode" );
        test.run();
    }

    public Inode createInode(){
        return m_msgFactory.createInode( new Date(), new Integer( 100 ), new Integer( 50 ) );
    }
    public void compare( Inode inode1, Inode inode2 ){

        if( !( inode1.getChangeTime().toString().equals( inode2.getChangeTime().toString() ) ) ){
            System.out.println( "Inode category is inconsistent!" );
            System.out.println( "Inode1.category = " + inode1.getChangeTime() );
            System.out.println( "Inode2.category = " + inode2.getChangeTime() );
        }
        if( !( inode1.getCMajorDevice().equals( inode2.getCMajorDevice() ) ) ){
            System.out.println( "Inode category is inconsistent!" );
            System.out.println( "Inode1.category = " + inode1.getCMajorDevice() );
            System.out.println( "Inode2.category = " + inode2.getCMajorDevice() );
        }
        if( !( inode1.getCMinorDevice().equals( inode2.getCMinorDevice() ) ) ){
            System.out.println( "Inode description is inconsistent!" );
            System.out.println( "Inode1.description = " + inode1.getCMinorDevice() );
            System.out.println( "Inode2.description = " + inode2.getCMinorDevice() );
        }
    }
    public void run(){
        Inode inode1 = createInode();
        Document document = m_docBuilder.newDocument();
        Node inodeNode = inode1.convertToXML( document );

        Inode inode2 = new Inode( inodeNode );
        compare( inode1, inode2 );

        document.appendChild( inodeNode );
        XMLUtils.printDocument( document );
    }
}
