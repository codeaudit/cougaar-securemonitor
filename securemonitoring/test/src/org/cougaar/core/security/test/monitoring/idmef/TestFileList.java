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

import edu.jhuapl.idmef.FileList;
import edu.jhuapl.idmef.IDMEF_File;
import edu.jhuapl.idmef.XMLUtils;

public class TestFileList extends TestIdmef {
    
    public TestFileList( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestFileList( "TestFileList" );
        test.init();
        test.run();
    }
    public void init(){
      m_fileTester = new TestFile();
      m_fileTester.init();
    }
    public FileList createFileList(){
      IDMEF_File files[] = { m_fileTester.createFile() };
      List fileList = convertToList( files );
      return m_msgFactory.createFileList( fileList ); 
    }
    public void compare( FileList fileList1, FileList fileList2 ){
      m_fileTester.compare( fileList1.getFiles(), fileList2.getFiles() ); 
    }
    public void run(){
        FileList fileList1 = createFileList();
        Document document = m_docBuilder.newDocument();
        Node fileListNode = fileList1.convertToXML( document );
        FileList fileList2 = new FileList( fileListNode );   
        compare( fileList1, fileList2 );
        
        document.appendChild( fileListNode );
        XMLUtils.printDocument( document );
    }
    private TestFile m_fileTester;
}
