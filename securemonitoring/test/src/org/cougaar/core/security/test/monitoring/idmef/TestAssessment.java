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

import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.XMLUtils;

public class TestAssessment extends TestIdmef {
    
    public TestAssessment( String name ){
        super( name );   
    }
    
    public static void main( String []args ){
        TestIdmef test = new TestAssessment( "TestAssessment" );
        test.init();
        test.run();
    }
    public void init(){
        m_impactTester = new TestImpact();
        m_actionTester = new TestAction();
        m_confidenceTester = new TestConfidence();
    }
    public Assessment createAssessment(){
        Impact impact = m_impactTester.createImpact();
        Confidence confidence = m_confidenceTester.createConfidence();
        Action actions[] = { m_actionTester.createAction() };
        List actionList = convertToList( actions );
        return m_msgFactory.createAssessment( impact, actionList, confidence );
    }
    public void compare( Assessment assessment1, Assessment assessment2 ){
        m_impactTester.compare( assessment1.getImpact(), assessment2.getImpact() );
        m_confidenceTester.compare( assessment1.getConfidence(), assessment2.getConfidence() );
        m_actionTester.compare( assessment1.getActions(), assessment2.getActions() );
    }
    public void run(){        
        Assessment assessment1 = createAssessment();
        Document document = m_docBuilder.newDocument();
        Node assessmentNode = assessment1.convertToXML( document );
        
        Assessment assessment2 = new Assessment( assessmentNode );
        compare( assessment1, assessment2 );
        document.appendChild( assessmentNode );
        XMLUtils.printDocument( document );
    }
    private TestImpact m_impactTester;
    private TestAction m_actionTester;
    private TestConfidence m_confidenceTester;
}
