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



package org.cougaar.core.security.test.javapolicy;


import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.cougaar.core.blackboard.BlackboardClient;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.servlet.AbstractServletComponent;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.io.PrintWriter;

import java.util.ArrayList;


/**
 * A Servlet that is supposed to have access granted to the $CIP/workspace
 * directory. If it does not, then an IDMEF Event is published to the
 * blackboard.
 *
 * @author ttschampel
 */
public class AuthorizedResourceServlet extends AbstractServletComponent implements BlackboardClient {
  private static final String SERVLET_PATH = "/AuthorizedResourceServlet";

  /**
   * Get path to this servlet
   *
   * @return DOCUMENT ME!
   */
  protected String getPath() {
    return SERVLET_PATH;
  }


  /**
   * Process Http request, just try to access resource
   *
   * @param request DOCUMENT ME!
   * @param response DOCUMENT ME!
   */
  protected void execute(HttpServletRequest request, HttpServletResponse response) {

    try {
      PrintWriter out=response.getWriter();
      try {
        String workspace = System.getProperty("org.cougaar.workspace");
        if (workspace == null) {
          if (logging.isErrorEnabled()) {
            logging.error("Workspace is null");
          }
          out.println("FALSE");
        } else {
          File file = new File(workspace + File.separator + "authorizedTest");
          FileWriter writer = new FileWriter(file);
          writer.write("TEST");
          writer.close();
          out.println("TRUE");
        }
      } catch (IOException se) {
        //create idmef event
        if (logging.isDebugEnabled()) {
          logging.debug("Could not access resource!");
        }
        out.println("FALSE");
        createIdmefEvent();
      }
      out.flush();
      out.close();
    } catch (Exception e) {
    }
  }


  private void createIdmefEvent() {
    DetectTime detectTime = new DetectTime();
    detectTime.setIdmefDate(new java.util.Date());
    CmrFactory cmrFactory = (CmrFactory) this.domainService.getFactory("cmr");
    ArrayList classifications = new ArrayList();
    Classification c = (Classification) cmrFactory.getIdmefMessageFactory().createClassification("Could not access resource", null);
    classifications.add(c);
    Analyzer a = cmrFactory.getIdmefMessageFactory().createAnalyzer(new SensorInfo() {
        public String getName() {
          return this.getClass().getName();
        }


        public String getManufacturer() {
          return "CSI";
        }


        public String getModel() {
          return "JavaPolicyTool";
        }


        public String getVersion() {
          return "1.0";
        }


        public String getAnalyzerClass() {
          return "JavaResourceAccessControlPlugin";
        }
      });

    Alert alert = cmrFactory.getIdmefMessageFactory().createAlert(a, detectTime, null, null, classifications, null);
    if (logging.isInfoEnabled()) {
      logging.info("*****************************Publishing IDMEF Event");
    }

    Event event = cmrFactory.newEvent(alert);

    if (!(event instanceof Serializable)) {
      if (logging.isErrorEnabled()) {
        logging.error("Event is not serializable");
      }
    }

    this.blackboardService.openTransaction();
    this.blackboardService.publishAdd(event);
    this.blackboardService.closeTransaction();
  }
}
