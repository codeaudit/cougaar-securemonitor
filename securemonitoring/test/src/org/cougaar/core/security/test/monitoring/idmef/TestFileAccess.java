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

import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.FileAccess;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.XMLUtils;

public class TestFileAccess extends TestIdmef {
    
    public TestFileAccess(){
        this( null );
    }
    public TestFileAccess( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestFileAccess( "TestFileAccess" );
        test.run();
    }
    public FileAccess createFileAccess(){
        //createFileAccess( String userId, String []permissions )
        String permissions[] = { "read", "write" };
        List permissionList = convertToList( permissions );
        return m_msgFactory.createFileAccess( "mluu", permissionList );   
    }
    public void compare( FileAccess []fileAccesses1, FileAccess []fileAccesses2 ){
        if( fileAccesses1.length == fileAccesses2.length ){
            int len = fileAccesses1.length;
            for( int i = 0; i < len; i++ ){
                compare( fileAccesses1[ i ], fileAccesses2[ i ] );
            }
        }
        else{
            System.out.println(" FileAccess lengths NOT EQUAL!" );
            System.out.println(" FileAccess1.length = " + fileAccesses1.length );
            System.out.println(" FileAccess2.length = " + fileAccesses2.length );
        }
        
    }
    public void compare( FileAccess fileAccess1, FileAccess fileAccess2 ){
        UserId user1 = fileAccess1.getUserId();
        UserId user2 = fileAccess2.getUserId();
        String permissions1[] = fileAccess1.getPermissions();
        String permissions2[] = fileAccess2.getPermissions();
        
        if( !( user1.getName().equals( user2.getName() ) ) ){
            System.out.println( "FileAccess user is inconsistent!" );
            System.out.println( "FileAccess1.user = " + user1.getName() );
            System.out.println( "FileAccess2.user = " + user2.getName() );
        }
        if( permissions1.length == permissions2.length ){
            int len = permissions1.length;
            for( int i = 0; i < len; i++ ){
                if( !( permissions1[ i ].equals( permissions2[ i ] ) ) ){
                    System.out.println( "FileAccess permission is inconsistent!" );
                    System.out.println( "FileAccess1.permission = " + permissions1[ i ] );
                    System.out.println( "FileAccess2.permission = " + permissions2[ i ] );
                }
            }
        }
        else{
            System.out.println(" FileAccess.permission lengths NOT EQUAL!" );
            System.out.println(" FileAccess1.permission.length = " + permissions1.length );
            System.out.println(" FileAccess2.permission.length = " + permissions2.length );
        }    
    }
    public void run(){
        FileAccess fileAccess1 = createFileAccess();
        Document document = m_docBuilder.newDocument();
        Node fileAccessNode = fileAccess1.convertToXML( document );
        
        FileAccess fileAccess2 = new FileAccess( fileAccessNode );
        compare( fileAccess1, fileAccess2 );
        
        document.appendChild( fileAccessNode );
        XMLUtils.printDocument( document );
    }
}
