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

import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;

import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public abstract class TestIdmef{
    
    public TestIdmef( String name ){
        m_name = name;
        m_msgFactory = new IdmefMessageFactory( null );
        try{
            m_docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        }
        catch( Exception e ){
            e.printStackTrace();
        }
    }
    public String getName(){
        return m_name;
    }
    public List convertToList( Object []listOfObjects ){
      int len  = listOfObjects.length;
      List list = new ArrayList();
      for( int i = 0; i < len; i++ ){
        list.add( i, listOfObjects[ i ] );
      }
      return list;
    }
    public IdmefMessageFactory getMessageFactory(){
        return m_msgFactory;
    }
    public void init(){}
    abstract public void run();

    // protected members
    protected IdmefMessageFactory m_msgFactory;
    protected DocumentBuilder m_docBuilder;
        
    // private members
    private String m_name;
}
