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

import org.cougaar.core.plugin.ComponentPlugin;
import org.cougaar.core.security.monitoring.blackboard.CmrFactory;
import org.cougaar.core.security.monitoring.blackboard.Event;
import org.cougaar.core.security.monitoring.blackboard.NewEvent;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.security.monitoring.idmef.RegistrationAlert;
import org.cougaar.core.service.DomainService;
import org.cougaar.core.service.LoggingService;

import java.util.ArrayList;
import java.util.List;

import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.FileList;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;

/** A dummy sensor used to show how to register capabilities and
 *  publish IDMEF events.
 *
 *  The cmr domain should be added to the node. This can be done by
 *  adding the following line in the LDMDomains.ini file:
 *     cmr=org.cougaar.core.security.monitoring.blackboard.CmrDomain
 */
public class DummySensor
  extends  ComponentPlugin
  implements SensorInfo
{
  private DomainService domainService = null;
  private LoggingService log;

  /**
   * Used by the binding utility through reflection to set my DomainService
   */
  public void setDomainService(DomainService aDomainService) {
    domainService = aDomainService;
  }

  /**
   * Used by the binding utility through reflection to get my DomainService
   */
  public DomainService getDomainService() {
    return domainService;
  }
    
  protected void setupSubscriptions() {
    log = (LoggingService)
	getBindingSite().getServiceBroker().getService(this,
	LoggingService.class, null);

    log.debug("setupSubscriptions of dummy sensor called :"); 
    DomainService service=getDomainService();
    if(service==null) {
      log.debug(" Got service as null in CapabilitiesConsolidationPlugin :");
      return;
    }
    CmrFactory factory=(CmrFactory)getDomainService().getFactory("cmr");
    if (factory == null) {
      log.debug("Error: Unable to get Monitoring Factory");
      return;
    }    
    IdmefMessageFactory imessage=factory.getIdmefMessageFactory();
    DummySensor sensor=new DummySensor();
	
    // create list of capabilities
    List capabilities = new ArrayList();
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.PingOfDeath",
						     "http://foo.com/security/pod.html",
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.TCPSCAN", null,
						     Classification.VENDOR_SPECIFIC  ) );
    capabilities.add( imessage.createClassification( "Cougaar.security.nai.LOGINFAILURE", null,
						     Classification.VENDOR_SPECIFIC  ) );
    // no need to specify targets since we may not know of the targets
    RegistrationAlert reg=
      imessage.createRegistrationAlert(this,
				       capabilities,IdmefMessageFactory.newregistration,IdmefMessageFactory.SensorType);
    // log.debug(" Registration object is :"+reg);
    log.debug("factory is :"+factory.toString());
    NewEvent event=factory.newEvent(reg);
    log.debug(" going to publish capabilities :");
    getBlackboardService().publishAdd(event);
    log.debug("Success in publishing  capabilities :");


    /* ---------------------------------------------------------------- */
    // ********************************
    // Source

    // Make a node
    Address source_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
               null, null)};
    IDMEF_Node source_node = new IDMEF_Node("locationA",
                                          "attackerA",
                                          source_address_list,
                                          "id01",
                                          IDMEF_Node.DNS);
    // Make a user
    UserId source_userId_list[] = {new UserId("Attacker_User",
				       new Integer (100),
				       "Test_Ident1", UserId.CURRENT_USER)};
    
    User source_user = new User(source_userId_list, "Test_Ident1", User.APPLICATION);

    // Make a Process
    String source_arg_list[] = {"-r", "-b", "12.3.4.5"};
    String source_env_list[] = {"HOME=/home/testuser/", "PATH=/usr/sbin"};
    IDMEF_Process source_process = new IDMEF_Process("Killer-process",
						     new Integer(666),
						     "/usr/bin/Killer",
						     source_arg_list, source_env_list,
						     "Test_IdentProcess1");
    // Create a service
    Service source_service = null;
    // Make a source
    Source source = imessage.createSource(source_node,
					  source_user,
					  source_process,
					  source_service,
					  Source.YES);
    ArrayList sources = new ArrayList(1);
    sources.add(source);

    // ********************************
    // Target

    // Make a node
    Address target_address_list[] =
    {new Address("10.1.1.1", null, null, null, null, null),
     new Address("0x0987beaf", null, null, Address.IPV4_ADDR_HEX,
               null, null)};
    IDMEF_Node target_node = new IDMEF_Node("locationB",
                                          "victimB",
                                          target_address_list,
                                          "id02",
                                          IDMEF_Node.DNS);
    // Make a user
    UserId target_userId_list[] = {new UserId("Victim_User",
					      new Integer (123),
					      "Test_Ident2", UserId.CURRENT_USER)};
    
    User target_user = new User(target_userId_list, "Test_Ident2", User.APPLICATION);

    // Make a Process
    String target_arg_list[] = {"12"};
    String target_env_list[] = {"HOME=/home/victimuser/", "PATH=/usr/sbin"};
    IDMEF_Process target_process = new IDMEF_Process("Node-process",
						     new Integer(1002),
						     "/usr/bin/Node",
						     target_arg_list, target_env_list,
						     "Test_IdentProcess");
    // Create a service
    Service target_service = null;
    // Create a file list
    FileList target_fileList = null;
    Target target = imessage.createTarget(target_node,
					  target_user,
					  target_process,
					  target_service,
					  target_fileList,
					  Target.YES);
    ArrayList targets = new ArrayList(1);
    targets.add(target);
    Classification classification =
      imessage.createClassification("cougaar_signature_exception",
				    "http://www.cougaar.org",
				    Classification.VENDOR_SPECIFIC);
    ArrayList classifications = new ArrayList(1);
    classifications.add(classification);
    ArrayList data = null;
    DetectTime detectTime = new DetectTime();
    Alert alert = imessage.createAlert(this, detectTime,
				       sources, targets,
				       classifications, data);
    Event e = factory.newEvent(alert);
    log.debug("Intrusion Alert:" + alert.toString());

    log.debug("Publishing sensor Event :");
    getBlackboardService().publishAdd(e);

  }
  public String getName(){
    return "Sample Sensor";
  }
  public String getManufacturer(){
    return "NAI Labs";
  }
  public String getModel(){
    return "Cougaar";
  }
  public String getVersion(){
    return "1.0";
  }
  public String getAnalyzerClass(){
    return "Security Analyzer";
  }
        
       
  protected void execute () {
    // process unallocated tasks
  }


}
