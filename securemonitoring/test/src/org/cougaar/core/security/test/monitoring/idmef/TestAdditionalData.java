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

// java xml packages
import org.cougaar.core.security.monitoring.idmef.Agent;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.XMLSerializable;
import edu.jhuapl.idmef.XMLUtils;

public class TestAdditionalData extends TestIdmef {
    public static String MEANING = "test-additional-data";
    
    public TestAdditionalData( String name ){
        super( name );
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestAdditionalData( "TestAdditionalData" );
        test.init();
        test.run();
    }
    public void init(){
      m_agentTester = new TestAgent();
    }
    public AdditionalData createAdditionalData(){
        Agent agent = m_agentTester.createAgent();
        return m_msgFactory.createAdditionalData( MEANING,
                                                  agent );
    }
    public void compare( AdditionalData ad1, AdditionalData ad2 ){
       String type1 = ad1.getType();
       String type2 = ad2.getType();
       if( !( type1.equals( type2 ) ) ){
            System.out.println( "Additional Data type is inconsistent!" );
            System.out.println( "AdditionalData1.type = " + ad1.getType() );
            System.out.println( "AdditionalData2.type = " + ad2.getType() );
        }
        if( !( ad1.getMeaning().equals( ad2.getMeaning() ) ) ){
            System.out.println( "Additional Data meaning is inconsistent!" );
            System.out.println( "AdditionalData1.meaning = " + ad1.getMeaning() );
            System.out.println( "AdditionalData2.meaning = " + ad2.getMeaning() );
        }
        if( type1.equals( type2 ) && type1.equals( AdditionalData.XML ) ){
            XMLSerializable xmlData1 = ad1.getXMLData();
            XMLSerializable xmlData2 = ad2.getXMLData();
            if( ( xmlData1 instanceof Agent ) && ( xmlData2 instanceof Agent ) ){
              m_agentTester.compare( ( Agent )xmlData1, ( Agent )xmlData2 );
            }
            else {
              System.out.println( "Additional XML Data type is inconsistent!" );
              System.out.println( "AdditionalData1.xmlData type = " + xmlData1.getClass().getName() );
              System.out.println( "AdditionalData2.xmlData type = " + xmlData2.getClass().getName() );    
            }
        }
        else if( !( ad1.getAdditionalData().equals( ad2.getAdditionalData() ) ) ){
            System.out.println( "Additional Data data is inconsistent!" );
            System.out.println( "AdditionalData1.data = " + ad1.getAdditionalData() );
            System.out.println( "AdditionalData2.data = " + ad2.getAdditionalData() );
        }
    }
    public void run(){
       
        Document document = m_docBuilder.newDocument();
        AdditionalData ad1 = createAdditionalData();
        
        Node adNode = ad1.convertToXML( document );
        AdditionalData ad2 = new AdditionalData( adNode );
        compare( ad1, ad2 );
        
        document.appendChild( adNode );
        XMLUtils.printDocument( document );
    }
    private TestAgent m_agentTester;
}
