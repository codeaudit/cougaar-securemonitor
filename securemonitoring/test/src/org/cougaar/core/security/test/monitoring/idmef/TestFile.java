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
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.FileAccess;
import edu.jhuapl.idmef.IDMEF_File;
import edu.jhuapl.idmef.Inode;
import edu.jhuapl.idmef.Linkage;
import edu.jhuapl.idmef.XMLUtils;

public class TestFile extends TestIdmef {
   
    public TestFile(){
        this( null );
    }
    public TestFile( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestFile( "TestFile" );
        test.init();
        test.run();
    }
    public void init(){
        m_fileAccessTester = new TestFileAccess();
        m_linkageTester = new TestLinkage();
        m_inodeTester = new TestInode();
    }
    
    public IDMEF_File createFile(){
        FileAccess []fileAccesses = { m_fileAccessTester.createFileAccess() };
        Linkage []linkages = { m_linkageTester.createLinkage() };
        Inode inode = m_inodeTester.createInode();
        List faList = convertToList( fileAccesses );
        List linkageList = convertToList( linkages );
        return m_msgFactory.createFile( new File( "/home/mluu/.ssh/id_rsa.pub" ), 
                                        faList,
                                        linkageList, 
                                        inode, 
                                        IDMEF_File.ORIGINAL,
                                        "fat16" );
    }
    public void compare( IDMEF_File []files1, IDMEF_File []files2 ){
        if( files1.length == files2.length ){
            int len = files1.length;
            for( int i = 0; i < len; i++ ){
                compare( files1[ i ], files2[ i ] );
            }
        }
        else{
            System.out.println(" Files lengths NOT EQUAL!" );
            System.out.println(" Files1.length = " + files1.length );
            System.out.println(" Files2.length = " + files2.length );
        }
    }
  
    public void compare( IDMEF_File file1, IDMEF_File file2 ){
        Date modifyTime1 = file1.getModifyTime();
        Date modifyTime2 = file2.getModifyTime();
        
        
        if( !( file1.getName().equals( file2.getName() ) ) ){
            System.out.println( "IDMEF_File name is inconsistent!" );
            System.out.println( "IDMEF_File1.name = " + file1.getName() );
            System.out.println( "IDMEF_File2.name = " + file2.getName() );
        }
        if( !( file1.getPath().equals( file2.getPath() ) ) ){
            System.out.println( "IDMEF_File path is inconsistent!" );
            System.out.println( "IDMEF_File1.path = " + file1.getPath() );
            System.out.println( "IDMEF_File2.path = " + file2.getPath() );
        }
        if( !( modifyTime1.toString().equals( modifyTime2.toString() ) ) ){
            System.out.println( "IDMEF_File modifyTime is inconsistent!" );
            System.out.println( "IDMEF_File1.modifyTime = " + modifyTime1.toString() );
            System.out.println( "IDMEF_File2.modifyTime = " + modifyTime2.toString() );
        }
        if( !( file1.getDataSize().equals( file2.getDataSize() ) ) ){
            System.out.println( "IDMEF_File dataSize is inconsistent!" );
            System.out.println( "IDMEF_File1.dataSize = " + file1.getDataSize() );
            System.out.println( "IDMEF_File2.dataSize = " + file2.getDataSize() );
        }
        m_fileAccessTester.compare( file1.getFileAccesses(), file2.getFileAccesses() );
        m_linkageTester.compare( file1.getLinkages(), file2.getLinkages() );
        m_inodeTester.compare( file1.getInode(), file2.getInode() );
        if( !( file1.getCategory().equals( file2.getCategory() ) ) ){
            System.out.println( "IDMEF_File category is inconsistent!" );
            System.out.println( "IDMEF_File1.category = " + file1.getCategory() );
            System.out.println( "IDMEF_File2.category = " + file2.getCategory() );
        }
        if( !( file1.getFstype().equals( file2.getFstype() ) ) ){
            System.out.println( "IDMEF_File fstype is inconsistent!" );
            System.out.println( "IDMEF_File1.fstype = " + file1.getFstype() );
            System.out.println( "IDMEF_File2.fstype = " + file2.getFstype() );
        }    
    }
    public void run(){
        IDMEF_File file1 = createFile();
        Document document = m_docBuilder.newDocument();
        Node fileNode = file1.convertToXML( document );
        
        IDMEF_File file2 = new IDMEF_File( fileNode );
        compare( file1, file2 );
        document.appendChild( fileNode );
        XMLUtils.printDocument( document );
    }
    private TestFileAccess m_fileAccessTester;
    private TestLinkage m_linkageTester;
    private TestInode m_inodeTester;
}
