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

import org.cougaar.core.security.monitoring.idmef.Agent;

import java.net.InetAddress;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Node;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.XMLUtils;

public class TestAgent extends TestIdmef {
    
    public TestAgent(){
        this( null );
    }
    public TestAgent( String name ){
        super( name );
    }
    public static void main( String []args ){
        TestIdmef test = new TestAgent( "TestAgent" );
        test.run();
    }
    public void init(){
     // m_addressTester = new TestAddress();
    }
    public Agent createAgent(){
        String refIdents[] = { "00000001", "00000002" };
        Address address = null;
        try {
            address = m_msgFactory.createAddress( InetAddress.getLocalHost().getHostAddress(), 
                                                  null, Address.IPV4_ADDR );
        }
        catch( Exception e ){
            e.printStackTrace();
        }
        List refIdList = convertToList( refIdents );
        return m_msgFactory.createAgent( "test-agent",
                                         "a test agent",
                                         "SF, CA",
                                         address,
                                         refIdList );
        
    }
  
    public void compare( Agent agent1, Agent agent2 ){
      String refList1[] = agent1.getRefIdents();
      String refList2[] = agent2.getRefIdents();
      Address address1 = agent1.getAddress();
      Address address2 = agent2.getAddress();
        if( !( agent1.getName().equals( agent2.getName() ) ) ){
            System.out.println( "Agent name is inconsistent!" );
            System.out.println( "Agent1.name = " + agent1.getName() );
            System.out.println( "Agent2.name = " + agent2.getName() );
        }
        if( !( agent1.getDescription().equals( agent2.getDescription() ) ) ){
            System.out.println( "Agent description is inconsistent!" );
            System.out.println( "Agent1.description = " + agent1.getDescription() );
            System.out.println( "Agent2.description = " + agent2.getDescription() );
        }
        if( !( agent1.getLocation().equals( agent2.getLocation() ) ) ){
            System.out.println( "Agent location is inconsistent!" );
            System.out.println( "Agent1.location = " + agent1.getLocation() );
            System.out.println( "Agent2.location = " + agent2.getLocation() );
        }
        // m_addressTester.compare( address1, address2 );
        if( !( address1.getAddress().equals( address2.getAddress() ) ) ){
            System.out.println( "Agent address is inconsistent!" );
            System.out.println( "Agent1.address = " + address1.getAddress() );
            System.out.println( "Agent2.address = " + address2.getAddress() );
        }
        if( !( address1.getCategory().equals( address2.getCategory() ) ) ){
            System.out.println( "Agent address category is inconsistent!" );
            System.out.println( "Agent1.address.category = " + address1.getCategory() );
            System.out.println( "Agent2.address.category = " + address2.getCategory() );
        }
        if( refList1.length == refList2.length ){
            int len = refList1.length;
            for( int i = 0; i < len; i++ ){
                if( !( refList1[ i ].equals( refList2[ i ] ) ) ){
                  System.out.println(" Agent.refList[ " + i + " ] is inconsistent!" );
                  System.out.println(" Agent.refList1[ " + i + " ] = " + refList1[ i ] );
                  System.out.println(" Agent.refList2[ " + i + " ] = " + refList2[ i ] );
                }
            }
        }
        else{
            System.out.println(" Agent.refList length NOT EQUAL!" );
            System.out.println(" Agent.refList1.length = " + refList1.length );
            System.out.println(" Agent.refList2.length = " + refList2.length );
        }
    }
    public void run(){
        Agent agent1 = createAgent();
        Document document = m_docBuilder.newDocument();
        Node agentNode = agent1.convertToXML( document );
        
        Agent agent2 = new Agent( agentNode );
        compare( agent1, agent2 );
        
        document.appendChild( agentNode );
        XMLUtils.printDocument( document );
    }
  //private TestAddress m_addressTester;
}
