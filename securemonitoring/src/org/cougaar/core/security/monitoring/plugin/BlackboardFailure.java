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



package org.cougaar.core.security.monitoring.plugin;


import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.util.UnaryPredicate;

import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;


/**
 * DOCUMENT ME!
 *
 * @version $Revision: 1.1 $
 * @author $author$
 */
public class BlackboardFailure implements UnaryPredicate,
    QueryClassificationProvider {
    private static final String[] CLASSIFICATIONS = {
        CompromiseBlackboard.CLASSIFICATION
    };

    /**
     * UnaryPredicate API requires this. Selects the objects that we're
     * interested in on the remote Blackboard.
     *
     * @param o DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean execute(Object o) {
        if (o instanceof Event) {
            Event event = (Event) o;
            if ((event.getEvent() != null) && event.getEvent() instanceof Alert) {
                Alert alert = (Alert) event.getEvent();
                if (alert.getClassifications() != null) {
                    Classification[] classifications = alert.getClassifications();
                    for (int i = 0; i < classifications.length; i++) {
                        if ((classifications[i].getName() != null)
                            && classifications[i].getName().equals(CompromiseBlackboard.CLASSIFICATION)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;


    }
    
    


    /**
     * QueryClassificationProvider requires this to get a list of sensors that
     * support LOGIN_FAILUREs.
     *
     * @return DOCUMENT ME!
     */
    public String[] getClassifications() {
        return CLASSIFICATIONS;
    }
}
