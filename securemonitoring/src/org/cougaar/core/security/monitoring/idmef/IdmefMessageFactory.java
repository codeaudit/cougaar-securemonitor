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

package org.cougaar.core.security.monitoring.idmef;

// java packages
import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.plugin.SensorInfo;
import org.cougaar.core.security.util.SystemUtils;
import org.cougaar.core.service.UIDServer;
import org.cougaar.planning.ldm.LDMServesPlugin;

import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Node;

import edu.jhuapl.idmef.Action;
import edu.jhuapl.idmef.AdditionalData;
import edu.jhuapl.idmef.Address;
import edu.jhuapl.idmef.Alert;
import edu.jhuapl.idmef.Analyzer;
import edu.jhuapl.idmef.AnalyzerTime;
import edu.jhuapl.idmef.Assessment;
import edu.jhuapl.idmef.Classification;
import edu.jhuapl.idmef.Confidence;
import edu.jhuapl.idmef.CreateTime;
import edu.jhuapl.idmef.DetectTime;
import edu.jhuapl.idmef.FileAccess;
import edu.jhuapl.idmef.FileList;
import edu.jhuapl.idmef.Heartbeat;
import edu.jhuapl.idmef.IDMEF_File;
import edu.jhuapl.idmef.IDMEF_Node;
import edu.jhuapl.idmef.IDMEF_Process;
import edu.jhuapl.idmef.Impact;
import edu.jhuapl.idmef.Inode;
import edu.jhuapl.idmef.Linkage;
import edu.jhuapl.idmef.Service;
import edu.jhuapl.idmef.Source;
import edu.jhuapl.idmef.Target;
import edu.jhuapl.idmef.User;
import edu.jhuapl.idmef.UserId;
import edu.jhuapl.idmef.XMLSerializable;

/********************************************************************* 
 * <pre>
 * Factory to create IDMEF messages
 *
 * 
 *                           +---------------+
 *                           | IDMEF-Message |
 *                           +---------------+
 *                                  /_\
 *                                   |
 *      +----------------------------+-------+
 *      |                                    |
 *  +-------+   +----------------+     +-----------+   +----------------+
 *  | Alert |<>-|    Analyzer    |     | Heartbeat |<>-|    Analyzer    |
 *  +-------+   +----------------+     +-----------+   +----------------+
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |<>-|   CreateTime   |     |           |<>-|   CreateTime   |
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |   +----------------+     |           |   +----------------+
 *  |       |<>-|   DetectTime   |     |           |<>-| AdditionalData |
 *  |       |   +----------------+     +-----------+   +----------------+
 *  |       |   +----------------+
 *  |       |<>-|  AnalyzerTime  |
 *  |       |   +----------------+
 *  |       |   +--------+   +----------+
 *  |       |<>-| Source |<>-|   Node   |
 *  |       |   +--------+   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-|   User   |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Process  |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Service  |
 *  |       |   +--------+   +----------+
 *  |       |   +--------+   +----------+
 *  |       |<>-| Target |<>-|   Node   |
 *  |       |   +--------+   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-|   User   |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +----------+
 *  |       |   |        |<>-| Process  |
 *  |       |   |        |   +----------+
 *  |       |   |        |   +--------- +
 *  |       |   |        |<>-| Service  |       +----------------+
 *  |       |   |        |   +----------+  +----| Classification |
 *  |       |   |        |   +----------+  |    +----------------+
 *  |       |   |        |<>-| FileList |  |    +----------------+
 *  |       |   +--------+   +----------+  | +--|   Assessment   |
 *  |       |<>----------------------------+ |  +----------------+
 *  |       |<>------------------------------+  +----------------+
 *  |       |<>---------------------------------| AdditionalData |
 *  +-------+                                   +----------------+
 *
 * Analyzer
 *     Exactly one.  Identification information for the analyzer that
 *     originated the alert.
 *
 *  CreateTime
 *     Exactly one.  The time the alert was created.  Of the three times
 *     that may be provided with an Alert, this is the only one that is
 *     required.
 *
 *  DetectTime
 *     Zero or one.  The time the event(s) leading up to the alert was
 *     detected.  In the case of more than one event, the time the first
 *     event was detected.  In some circumstances, this may not be the
 *     same value as CreateTime.
 *
 *  AnalyzerTime
 *     Zero or one.  The current time on the analyzer (see Section 7.3).
 *
 *  Source
 *     Zero or more.  The source(s) of the event(s) leading up to the
 *     alert.
 *
 *  Target
 *     Zero or more.  The target(s) of the event(s) leading up to the
 *     alert.
 *
 *  Classification
 *     One or more.  The "name" of the alert, or other information
 *     allowing the manager to determine what it is.
 *
 *  Assessment
 *     Zero or one.  Information about the impact of the event, actions
 *     taken by the analyzer in response to it, and the analyzer's
 *     confidence in its evaluation.
 *
 *  AdditionalData
 *     Zero or more.  Information included by the analyzer that does not
 *     fit into the data model.  This may be an atomic piece of data, or
 *     a large amount of data provided through an extension to the IDMEF
 *     (see Section 6).
 *
 *  Because DTDs do not support subclassing (see Section 4.3.4), the
 *  inheritance relationship between Alert and the ToolAlert,
 *  CorrelationAlert, and OverflowAlert subclasses shown in Figure 5.2
 *  has been replaced with an aggregate relationship.
 *
 *  Alert is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Alert                         (
 *         Analyzer, CreateTime, DetectTime?, AnalyzerTime?, Source*,
 *         Target*, Classification+, Assessment?, (ToolAlert |
 *         OverflowAlert | CorrelationAlert)?, AdditionalData*
 *     )&gt
 *     &lt!ATTLIST Alert
 *         ident               CDATA                   '0'
 *     &gt
 *
 *  The Alert class has one attribute:
 *
 *  ident
 *     Optional.  A unique identifier for the alert.
 * </pre>
 *
 ********************************************************************/
final public class IdmefMessageFactory {

  public static String CLASSIFICATION_ORIGIN = "Cougaar";
  public static final int newregistration=1;
  public static final int addtoregistration=2;
  public static final int removefromregistration=3;
  public static final String SensorType="Sensor";
  public static final String SecurityMgrType="SecurityManager";
  public static final String UnknownType="Unknown";
  private ServiceBroker serviceBroker;

  /**
   * Constructor to create an IdmefMessageFactory instance
   *
   * @param ldm the LDMServesPlugin
   */
  public IdmefMessageFactory(LDMServesPlugin ldm ){
        
    String agentName = "unknown";
    Address agentAddress = null;
        
    m_ldm = ldm;
    m_osName = System.getProperty( "os.name" );
    m_osVersion = System.getProperty( "os.version" ); 
      
        if( ldm != null ){
            String ip = "localhost";
            String vmInfo = SystemUtils.getVMInfo();
            String vmPath = SystemUtils.getJavaHome();
            // get the program arguments
            List progArgs = SystemUtils.getCmdLineArgs();
            // get the env variables
            List envVars = SystemUtils.getEnvs();
                        
            try{
                ip = InetAddress.getLocalHost().getHostAddress();
            }
            catch( UnknownHostException uhe ){
                // what should we do here?
            }

            List addressList = new ArrayList();
            addressList.add( createAddress( ip, null, Address.IPV4_ADDR ) );
            m_agentId = ldm.getMessageAddress();
            m_uidServer = ldm.getUIDServer();
            /*
             * can get the process name
             * cannot get the process id since java doesn't provide you with an api to do so!
             * can get the path 
             * can get the program arguments via the System.getProperty( ArgTableIfc.<names> );
             * can get the env variables
             */ 
            m_process = createProcess( vmInfo, 
                                       null,  // can't get the pid from java without using native methods
                                       vmPath, 
                                       progArgs, 
                                       envVars ); // get the process info from the LDMServesPlugin ( program name, args, env, etc.. )
            /**
             * name and address
             * get the name from the System.getProperty( ArgTableIfc.NAME_KEY );
             * get the address from
             *
             */

            m_node = createNode( SystemUtils.getNodeName(),
                                 addressList );    // get the node info from the LDMServesPlugin ( name and address )
            agentName = m_agentId.toString();
            agentAddress = createAddress( m_agentId.getAddress(), null, Address.URL_ADDR );
	    String username=System.getProperty( "user.name" );
	    UserId userid=createUserId(username);
	    List useridlist=new ArrayList();
	    useridlist.add(userid);
	    m_user=createUser(useridlist);
        }
        
    m_agent = createAgent( agentName,
			                     null,  // description
			                     null,  // location
			                     agentAddress,
			                     null );
  }
    
  /** 
   * Stub Factory method to create an alert.
   *
   * @return a stub alert message
   */
  public Alert createAlert()
    {
      /** 
       * Make  an IPv4 address for the current host
       * The Address class is  used to represent network, hardware, and
       * application addresses.
       */
      Address address_list[] = 
      { new Address( "1.1.1.1", null, null, null, null, null ),
	new Address( "0x0987beaf",   null, null, Address.IPV4_ADDR_HEX, null, null ) };

      /** Make a Node object for the current host
       * The Node  class is used to identify hosts and other network devices
       * (routers, switches, etc.).
       */
      IDMEF_Node testNode = new IDMEF_Node( "Test Location", 
					    "Test Name", 
					    address_list, 
					    "Test_Ident", 
					    IDMEF_Node.DNS );
    
      /** 
       * Make a user
       * The User  class is used to describe users.  It is primarily used as a
       * "container" class for the UserId aggregate class
       */
      UserId userId_list[] = { new UserId( "Test_Name", 
					   new Integer(100), 
					   "Test_Ident",
					   UserId.CURRENT_USER ) };
        
      User testUser = new User(userId_list, "Test_Ident",
			       User.APPLICATION);
        
        
      //make a Process
      String arg_list[] = {"-r", "-b", "12.3.4.5"};
      String env_list[] = {"HOME=/home/mccubb/", "PATH=/usr/sbin"};
      IDMEF_Process testProcess =
        new IDMEF_Process( "Test_Name", 
                           new Integer(1002), 
                           "/usr/sbin/ping",
                           arg_list, env_list, 
                           "Test_Ident" );
        
      //make a service
      Service testService = new Service( "Test_Name", new Integer(23), 
					 "26, 8, 100-1098", "telnet",
					 "test_ident" );

      //make an analyzer
      Analyzer testAnalyzer = new Analyzer( testNode, testProcess, "test_id", 
					    "test_manufacturer", "test_model",
					    "test_version", "test_class", m_osName,
					    m_osVersion );
        
      //make a createTime
      //make a detectTime
      //make a AnalyzerTime
        
      DetectTime d = new DetectTime ();
      CreateTime c = new CreateTime();
      AnalyzerTime a = new AnalyzerTime();

      //make a target list

      Target target[] = { new Target( testNode, 
				      testUser, 
				      testProcess, 
				      testService,
				      null, 
				      "test_ident", 
				      Target.YES, 
				      "/dev/eth0" ) };

      //make a source list
    
      Source source[] = { new Source( testNode, 
				      testUser, 
				      testProcess, 
				      testService, 
				      "test_ident", 
				      Source.YES, 
				      "/dev/eth0" ) };
    
      //make a Classification list
      Classification testClassification[] = { new Classification("Test_Name", 
								 "http://www.yahoo.com", Classification.CVE)};
      //make an Assessment
      Impact impact = new Impact( Impact.HIGH,
				  Impact.SUCCEEDED,
				  Impact.OTHER,
				  "test_impact" );
      Action actions[] = { new Action( Action.OTHER, "test_action" ) };
      Confidence confidence = new Confidence( Confidence.NUMERIC, new Float( 0.5f ) );					  
      Assessment testAssessment = new Assessment( impact, actions, confidence );
	    
      //make an additionalData list
      AdditionalData ad[] = {new AdditionalData (AdditionalData.INTEGER, 
						 "Chris' Age", "24")};
    
    
      Alert theAlert =
	new Alert(testAnalyzer, c, d, a, source, target,
		  testClassification, testAssessment, ad, 
		  "test_ident" );
    
      return theAlert;
    }
    
  /**
   * Factory method to create an IDMEF Alert.
   *
   * @param analyzer the analyzer that originated the alert
   * @param detectTime the time the first event was detected
   * @param sourceList list of sources that are involved in the event
   * @param targetList list of targets that are involved in the event
   * @param classificationList list of classification for the event
   * @param dataList list of additional data that may be useful
   *
   * @return an Alert message
   */
  public Alert createAlert( Analyzer analyzer,
			    DetectTime detectTime,
			    List sourceList,
			    List targetList,
			    List classificationList,
			    List dataList ){
    Source sources[] = null;
    Target targets[] = null;
    Classification classifications[] = null;
    AdditionalData data[] = null;
    
    if( sourceList != null )
      sources = ( Source [] )sourceList.toArray( ( new Source[ 0 ] ) );
    if( targetList != null )
      targets = ( Target [] )targetList.toArray( ( new Target[ 0 ] ) );
    if( classificationList != null )
      classifications = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
    
    if( dataList == null ){
      dataList = new ArrayList(1);
    }
    
    if( dataList != null ){
      // add agent info to the alert
      if( analyzer != null ){
        List refList = new ArrayList();
        refList.add( analyzer.getAnalyzerid() );
        Agent newAgent = ( Agent )m_agent.clone();
        newAgent.setRefIdents( ( String [] )refList.toArray( new String[ 0 ] ) );
        dataList.add( createAdditionalData( Agent.AGENT_INFO_MEANING,
					                                  newAgent ) ); 
      } 
      if( dataList.size() != 0 ) {
        data = ( AdditionalData [] )dataList.toArray( ( new AdditionalData[ 0 ] ) );
      }
    }
   
    return new Alert( analyzer,
		      new CreateTime(),
		      detectTime,           // is this needed? if not, null.
		      null,                 // is this needed? if not, null.
		      sources,
		      targets,
		      classifications,
		      null,                 // assessment null for now
		      data,
		      createUniqueId() );  // this unique id is used for consolidated events
  }
    
  /**
   * Factory method to create an IDMEF Alert.
   *
   * @param analyzer the analyzer that originated the alert
   * @param detectTime the time the first event was detected
   * @param sourceList list of sources that are involved in the event
   * @param targetList list of targets that are involved in the event
   * @param classificationList list of classification for the event
   * @param dataList list of additional data that may be useful
   *
   * @return an Alert message
   */
  public Alert createAlert( Object sensor,
			    DetectTime detectTime,
			    List sourceList,
			    List targetList,
			    List classificationList,
			    List dataList ){
      return createAlert( createAnalyzer( sensor ),
			                    detectTime,
			                    sourceList,
			                    targetList,
			                    classificationList,
			                    dataList );
  }
    
  public Alert createAlert( Node alertNode ){
    return new Alert( alertNode );   
  }
    
  /**
   *
   * Factory method to create a message for sensor capability registration.
   *
   * @param sensor the sensor creating a registration message
   * @param classficationList a list of events the sensor is capable of tracking
   * @param targetList a list of targets the sensor is monitoring
   *
   * @return a capability Registration message
   */
  public RegistrationAlert createRegistrationAlert( Object sensor, 
					            List classificationList,
					            List targetList,
					            int op_type , String type){
    // get all the info from the sensor for capability registration
    if( sensor instanceof SensorInfo ){ 
      Classification capabilities[] = null;
      Target targets[] = null;
      if( classificationList != null )
	      capabilities = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
	    if( targetList != null )
        targets = ( Target [] )targetList.toArray( ( new Target[ 0 ] ) );
          
      //TODO: move string constants to appropriate classes
      AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
						      "cougaar-alert-type", 
						      type ) };
        
      return new RegistrationAlert( createAnalyzer( sensor ), 
			       null, // very difficult to know the sources at this point
			       targets,
			       capabilities,
			       data,
			       createUniqueId(),
			       op_type,type, m_agent.getName()); 
    }
    return new RegistrationAlert();
  }

 /**
   *
   * Factory method to create a message for sensor capability registration.
   *
   * @param sensor the sensor creating a registration message
   * @param classficationList a list of events the sensor is capable of tracking
   * @param targetList a list of targets the sensor is monitoring
   *
   * @return a capability Registration message
   */
  public RegistrationAlert createRegistrationAlert( Object sensor, 
					  List classificationList,
					  int op_type ,String type){
    // get all the info from the sensor for capability registration
    if( sensor instanceof SensorInfo ){ 
      Classification capabilities[] = null;
      if( classificationList != null )
	      capabilities = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
               
      //TODO: move string constants to appropriate classes
      AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
						      "cougaar-alert-type", 
						      type ) };
        
      return new RegistrationAlert( createAnalyzer( sensor ), 
			       null, // very difficult to know the sources at this point
			       null,
			       capabilities,
			       data,
			       createUniqueId(),op_type,type,m_agent.getName() ); 
    }
    return new RegistrationAlert();
  }
   public RegistrationAlert createRegistrationAlert( Object sensor, 
					  List classificationList,
					  int op_type ,String type, String agentName){
    // get all the info from the sensor for capability registration
    if( sensor instanceof SensorInfo ){ 
      Classification capabilities[] = null;
      if( classificationList != null )
	      capabilities = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
               
      //TODO: move string constants to appropriate classes
      AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
						      "cougaar-alert-type", 
						      type ) };
        
      return new RegistrationAlert( createAnalyzer( sensor ), 
			       null, // very difficult to know the sources at this point
			       null,
			       capabilities,
			       data,
			       createUniqueId(),op_type,type,agentName); 
    }
    return new RegistrationAlert();
  }
  
  public RegistrationAlert createRegistrationAlert( Analyzer analyzer,
						    List sourceList,
						    List targetList,
						    List classificationList,
						    List additionaldataList,
						    int operationtype,String type, String agentName){
    Classification [] classification=null;
    Source [] sources=null;
    Target [] targets=null;
    AdditionalData [] additionaldata=null;
    if(sourceList!=null)
      sources = ( Source [] )sourceList.toArray( ( new Source[ 0 ] ) );

    if(targetList!=null) 
       targets = ( Target [] )targetList.toArray( ( new Target[ 0 ] ) );
    
    if( classificationList != null )
      classification = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
    
    if(additionaldataList!=null) {
      
       AdditionalData [] tempdata=( AdditionalData [] )additionaldataList.toArray( ( new AdditionalData[ 0 ] ) );
       additionaldata = new AdditionalData[tempdata.length+1];
       additionaldata[0]= createAdditionalData( AdditionalData.STRING, 
						"cougaar-alert-type", 
						type ) ;
       System.arraycopy(tempdata,0,additionaldata,1,tempdata.length);
      
    }
    else {
      additionaldata=new AdditionalData[1];
      additionaldata[0]= createAdditionalData( AdditionalData.STRING, 
					       "cougaar-alert-type", 
					       type ) ;
    }
    return  new RegistrationAlert(analyzer,sources,targets,classification,additionaldata,createUniqueId(),operationtype,type,agentName);
  }
  
  public RegistrationAlert createRegistrationAlert( Object sensor ,
						    List sourceList,
						    List targetList,
						    List classificationList,
						    List additionaldataList,
						    int operationtype,String type, String agentName){
    Classification [] classification=null;
    Source [] sources=null;
    Target [] targets=null;
    AdditionalData [] additionaldata=null;
    if( sensor instanceof SensorInfo ){ 
      if(sourceList!=null)
	sources = ( Source [] )sourceList.toArray( ( new Source[ 0 ] ) );
      
      if(targetList!=null) 
	targets = ( Target [] )targetList.toArray( ( new Target[ 0 ] ) );
      
      if( classificationList != null )
	classification = ( Classification [] )classificationList.toArray( ( new Classification[ 0 ] ) );
      
      if(additionaldataList!=null) {
	AdditionalData [] tempdata=( AdditionalData [] )additionaldataList.toArray( ( new AdditionalData[ 0 ] ) );
	additionaldata = new AdditionalData[tempdata.length+1];
	additionaldata[0]= createAdditionalData( AdditionalData.STRING, 
						 "cougaar-alert-type", 
						 type ) ;
	System.arraycopy(tempdata,0,additionaldata,1,tempdata.length);
	
      }
      else {
	additionaldata=new AdditionalData[1];
	additionaldata[0]= createAdditionalData( AdditionalData.STRING, 
						 "cougaar-alert-type", 
						 type ) ;
      }
      return  new RegistrationAlert( createAnalyzer( sensor ),sources,targets,classification,additionaldata,createUniqueId(),operationtype,type,agentName);
    }
    return new RegistrationAlert(); 
  }
  
  
  /**
   * Factory method to create initial consolidated capabilities.
   *
   * @return a  consolidated capabilities  message
   */
  public ConsolidatedCapabilities  createConsolidatedCapabilities( ){
    // update all info when first capability registration object
    Analyzer analyzer = null; 
    Source sources[] = null; // get the source info from the sensor
    Target targets[] = null; // get the target info from the sensor
    Classification capabilities[] = null;  // get the capabilities from the sensor
    AdditionalData data[] = { createAdditionalData( AdditionalData.STRING, 
						    "cougaar-alert-type", 
						     IdmefMessageFactory.UnknownType) };
                                                        
    return new ConsolidatedCapabilities(analyzer,
					sources,
					targets, 
					capabilities,
					data,
					createUniqueId(),IdmefMessageFactory.UnknownType,m_agent.getName());
  }
    
  /** 
   * Factory method to create a heartbeat.
   *
   * @param analyzer analyzer creating the heartbeat                   
   * @param dataList a list of additional data
   *
   * @return a Heartbeat message
   */
  public Heartbeat createHeartBeat( Analyzer analyzer, 
				    List dataList ){
    AdditionalData data[] = null;
    if( dataList != null )
      data = ( AdditionalData [] )dataList.toArray( ( new AdditionalData[ 0 ] ) );
    Heartbeat heartBeat = new Heartbeat( analyzer, 
					 new CreateTime(), 
					 null,   //  analyzer time not used
					 data,   
					 null ); // ident not used at the moment
    return heartBeat;
  }
    
  /** 
   * Factory method to create a heartbeat.
   *
   * @param sensor the sensor that is creating this heartbeat
   * @param dataList list of additional data
   *
   * @return a Heartbeat message
   */
  public Heartbeat createHeartBeat( Object sensor,
				    List dataList ){
    if( sensor instanceof SensorInfo ){
      return createHeartBeat( createAnalyzer( sensor ), dataList );
    }
    return new Heartbeat();
  }
     
  /**
   * Factory method to create an Analyzer
   *
   * @param sensor analyzer object containing pertinent info such as id,
   *               manufacturer, model, version, etc..
   *
   * @return an Analyzer object
   */
  public Analyzer createAnalyzer( Object sensor ){
        
    if( sensor instanceof SensorInfo ){
      SensorInfo sensorInfo = ( SensorInfo )sensor;
      String analyzerId = m_agent.getName() + "/" + sensorInfo.getName();           // get the sensor id
      String manufacturer = sensorInfo.getManufacturer(); // get the sensor manufacturer
      String model = sensorInfo.getModel();               // get the sensor model
      String version = sensorInfo.getVersion();           // get the sensor version
      String analyzerClass = sensorInfo.getAnalyzerClass();    // get the sensor class
      // this info can be determined at factory initialization
      IDMEF_Node node = m_node;             // get the node that the sensor resides
      IDMEF_Process process = m_process;    // get the process that the sensor resides
        
      return new Analyzer( node,  // node 
			   process,  // process
			   analyzerId,
			   manufacturer,  // manufacturer
			   model,  // model
			   version,  // version
			   analyzerClass,  // class
			   m_osName,
			   m_osVersion );
    }
    return new Analyzer();
  }
                                           
  /**
   * Factory method to create an Analyzer
   *
   * @param analyzerId unique across all analyzers in the intrusion 
   *                   detection environment.  The analyzerId MUST be
   *                   unique.  One way to obtain uniqueness is to
   *                   combine the agent id where the sensor rides
   *                   with the sensor name.   For example the format
   *                   is of the following (without quotes):
   *                   "&ltagent address&gt/&ltsensor name&gt"
   *
   * @return an Analyzer object
   */
  public Analyzer createAnalyzer( String analyzerId,
				  String manufacturer,
				  String model,
				  String version,
				  String analyzerClass ){
    // this info can be determined at factory initialization
    IDMEF_Node node = m_node;             // get the node that the sensor resides
    IDMEF_Process process = m_process;    // get the process that the sensor resides
    return new Analyzer( node,  // node 
			 process,  // process
			 analyzerId,
			 manufacturer,  // manufacturer
			 model,  // model
			 version,  // version
			 analyzerClass,  // class
			 m_osName,
			 m_osVersion );
  }
    
  /**
   * Factory method to create a Source
   *
   * @param node node host or device on which the analyzer resides 
   * @param user a user of the system, device, or application
   * @param process describe processes being executed on a sources
   * @param service network services on source
   * @param spoofed indication of whether the source is, as far as the
   *                analyzer can determine, a decoy.  
   *                <br>Permitted values:<br>
   *                <code>Source.YES, Source.NO, Source.UNKNOWN</code>
   *
   * @return a Source object
   */ 
  public Source createSource( IDMEF_Node node, 
			      User user,
			      IDMEF_Process process,
			      Service service,
			      String spoofed ){
    return new Source( node, 
		       user, 
		       process, 
		       service, 
		       createUniqueId(), // needed to associate agent information
		       spoofed, 
		       null );  // network interface not necessary
    
  }
    
  /**
   * Factory method to create a Node
   *
   * @param name the name of a node
   * @param addressList a list of Addresses
   *
   * @return an IDMEF_Node object
   */    
  public IDMEF_Node createNode( String name, List addressList ){
    
    Address addresses[] = null;
    if( addressList != null )
      addresses = ( Address [] )addressList.toArray( ( new Address[ 0 ] ) );
    return new IDMEF_Node( null,  // location not necessary
			   name, 
			   addresses, 
			   null,  // unique id not necessary
			   null ); // category not necessary
  }
    
  /**
   * Factory method to create a Process
   *
   * @param program the name of the program being executed
   * @param pid the process id
   * @param path the full path of the program being executed
   * @param argList a list of the command-line arguments to the program
   * @param envList a list the environment string associated with the
   *             process; generally of the format "[VARIABLE=value]".  
   *
   * @return an IDMEF_Process object
   */
  public IDMEF_Process createProcess( String program, 
				      Integer pid, 
				      String path, 
				      List argList, 
				      List envList ){
      String args[] = null;
      String envs[] = null;
      if( argList != null )
        args = ( String [] )argList.toArray( ( new String[ 0 ] ) );  
      if( envList != null )
        envs = ( String [] )envList.toArray( ( new String[ 0 ] ) );
       return new IDMEF_Process( program, 
			                           pid, 
	                     		       path, 
			                           args, 
			                           envs, 
			                           null ); // unique id not necessary
  }
          
  /**
   * Factory method to create a User
   *
   * @param userIdList a list of unique ids of the user
   *
   * @return a User object
   */
  public User createUser( List userIdList ){
    UserId userIds[] = null;
    if( userIdList != null )
    userIds = ( UserId [] )userIdList.toArray( ( new UserId[ 0 ] ) );
    return new User( userIds, null, null );
  }
   
  /**
   * Factory method to create a Service
   *
   * @param name the name of the service
   * @param protocol the protocol being used (optional)
   *
   * @return a Service object
   */
  public Service createService( String name, String protocol ){
    return new Service( name, 
			null, 
			null, 
			protocol, 
			null ); // ident not necessary
  }
    
  /**
   * Factory method to create a Service
   *
   * @param port the port number being used
   * @param protocol the protocol being used (optional)
   *
   * @return a Service object
   */
  public Service createService( Integer port, String protocol ){
    return new Service( null, 
			port, 
			null, 
			protocol, 
			null ); // ident not necessary
  }
    
  /**
   * Factory method to create a Service
   *
   * @param name the name of the service
   * @param port the port number being used
   * @param protocol the protocol being used (optional)
   *
   * @return a Service object
   */
  public Service createService( String name, Integer port, String protocol ){
    return new Service( name, 
			port, 
			null, 
			protocol, 
			null ); // ident not necessary
  }
    
  /**
   * Factory method to create a Service with port list
   *
   * @param portList - Port lists consist of a comma-separated list of numbers 
   *                    (individual integers) and ranges (N-M means ports N through 
   *                    M, inclusive).  Any combination of numbers and ranges may be
   *                    used in a single list.  For example, 
   *                    "5-25,37,42,43,53,69-119,123-514".
   * @param protocol - The protocol being used (optional)
   */
  public Service createServiceWithPortList( String portList, String protocol ){
    return new Service( null, 
			null, 
			portList, 
			protocol, 
			null ); // ident not necessary
  }
    
  /**
   * Factory method to create a FileList
   *
   * @param fileList list of files targeted in this event
   *
   * @return a FileList object
   */
  public FileList createFileList( List fileList ){
    
    IDMEF_File files[] = null;
    if( fileList != null )
      files = ( IDMEF_File [] )fileList.toArray(  ( new IDMEF_File[ 0 ] )  );
    return new FileList( files );
  }
    
  /**
   * Factory method to create a Target 
   *
   * @param node information about the host or device at which the
   *             event(s) (network address, network name, etc.) is
   *             being directed
   * @param user information about the user at which the event(s) is
   *             being directed
   * @param process information about the process at which the event(s) is
   *                being directed
   * @param service information about the service at which the event(s) is
   *                being directed
   * @param fileList information about file(s) involved in the event(s)
   * @param decoy an indication of whether the target is, as far as the
   *             analyzer can determine, a decoy.  The permitted values
   *             for this attribute are shown below.  The default value
   *             is "unknown".
   * <pre>
   * Rank   Keyword           Description
   * ----   -------           -----------
   *   0    Target.UNKNOWN    Accuracy of target information unknown
   *   1    Target.YES        Target is believed to be a decoy
   *   2    Target.NO         Target is believed to be "real"
   * </pre>
   * @return a Target object
   */
  public Target createTarget( IDMEF_Node node, 
			      User user,
			      IDMEF_Process process,
			      Service service,
			      FileList fileList,
			      String decoy ){
    return new Target( node, 
		       user, 
		       process, 
		       service,
		       fileList,
		       createUniqueId(), 
		       decoy, 
		       null );
  }
    
  /**
   * Factory method to create a Classification
   *
   * @param name The name of the alert classification.
   * @param url a URL at which the manager (or the human
   *            operator of the manager) can find additional information about the
   *            alert.  The document pointed to by the URL may include an in-depth
   *            description of the attack, appropriate countermeasures, or other
   *            information deemed relevant by the vendor.
   * @param type The source from which the name of the alert originates.
   *             The permitted values for this attribute are shown below.  The
   *             default value is "unknown". (Required)
   * <pre>
   * Rank   Keyword                           Description
   * ----   -------                           -----------
   *   0    Classification.UNKNOWN            Origin of the name is not known
   *   1    Classification.BUGTRAQID          The SecurityFocus.com ("Bugtraq")
   *                                          vulnerability database identifier
   *                                          (http://www.securityfocus.com/vdb)
   *   2    Classification.CVE                The Common Vulnerabilities and Exposures
   *                                          (CVE) name (http://www.cve.mitre.org/)
   *   3    Classification.VENDOR_SPECIFIC    A vendor-specific name (and hence, URL);
   *                                          this can be used to provide product-
   *                                          specific information
   * </pre>
   * @return a Classification object
   */
  public Classification createClassification( String name, 
					      String url, 
					      String type ){
    return new Classification( name, 
			       url, 
			       type );
  }
    
  /**
   * Factory method to create a vendor-specific Classification
   *
   * @param name The name of the alert classification.
   * @param url A URL at which the manager (or the human
   *            operator of the manager) can find additional information about the
   *            alert.  The document pointed to by the URL may include an in-depth
   *            description of the attack, appropriate countermeasures, or other
   *            information deemed relevant by the vendor.
   *
   * @return a Classification object
   */
  public Classification createClassification( String name, String url ){
    return createClassification( name, 
				 url, 
				 Classification.VENDOR_SPECIFIC );     
  }
    
  /**
   * Factory method to create an Assessment
   *
   * @param impact The analyzer's assessment of the impact of the event
   *               on the target(s).
   * @param actionList A list of action(s) taken by the analyzer in response to
   *                   the event.
   * @param confidence A measurement of the confidence the analyzer has
   *                   in its evaluation of the event.
   *
   * @return an Assessment object
   */
  public Assessment createAssessment( Impact impact, List actionList, Confidence confidence ){
    Action actions[] = null;
    if( actionList != null )
      actions = ( Action [] )actionList.toArray( ( new Action[ 0 ] ) );
    return new Assessment( impact, actions, confidence );
  }
 
  /**
   * Factory method to create an AdditionalData
   *
   * @param type The type of data included in the element content.
   *             The permitted values for this attribute are shown 
   *             below.  The default value is "string".
   * <pre>
   * Rank   Keyword                   Description
   * ----   -------                   -----------
   *   0    AdditionalData.BOOLEAN    The element contains a boolean value,
   *                                  i.e., the strings "true" or "false"
   *   1    AdditionalData.BYTE       The element content is a single 8-bit
   *                                  byte
   *   2    AdditionalData.CHARACTER  The element content is a single
   *                                  character
   *   3    AdditionalData.DATE_TIME  The element content is a date-time
   *   4    AdditionalData.INTEGER    The element content is an integer
   *   5    AdditionalData.NTPSTAMP   The element content is an NTP timestamp
   *   6    AdditionalData.PORTLIST   The element content is a list of ports
   *   7    AdditionalData.REAL       The element content is a real number
   *   8    AdditionalData.STRING     The element content is a string
   *   9    AdditionalData.XML        The element content is XML-tagged data
   * </pre>
   * @param meaning A string describing the meaning of the element content.
   *                These values will be vendor/implementation dependent; 
   *                the method for ensuring that managers understand the
   *                strings sent by analyzer is outside the scope of this
   *                specification. (Optional)
   * @param data atomic data (integers, strings, etc.) in cases where only
   *             small amounts of additional information need to be sent;
   *             it can also be used to transmission of complex data (such as
   *             packet headers).
   *
   * @return an AdditionalData object
   */
  public AdditionalData createAdditionalData( String type, 
					      String meaning, 
					      String data ){
    return new AdditionalData( type, 
			       meaning, 
			       data );
  }
  
  /**
   * Factory method to create an AdditionalData
   *
   * @param meaning A string describing the meaning of the xml data (Optional).
   * @param data an XMLSerializable data
   *
   * @return an AdditionalData object
   */
  public AdditionalData createAdditionalData( String meaning, 
					                                    XMLSerializable data ){
    return new AdditionalData(  meaning, 
			                          data );
  } 
  /**
   * Factory method to create an IDMEF File
   * 
   * @param file the file associated with this alert
   * @param fileAccesseList list of the file access permissions
   * @param linkageList list of other files that this file references
   * @param inode additional information contained in a Unix file system i-node
   * @param category the context for the information being provided
   * @param fstype the file system type
   *
   * @return an IDMEF_File object
   */
  public IDMEF_File createFile( File file, 
				List fileAccessList,
				List linkageList, 
				Inode inode, 
				String category,
				String fstype ){
	  
    FileAccess fileAccesses[] = null;
    Linkage linkages[] = null;
    Integer dataSize = null;
    Date modifiedDate = null;
    
    if( fileAccessList != null )
      fileAccesses = ( FileAccess [] )fileAccessList.toArray( ( new FileAccess[ 0 ] ) );
    if( linkageList != null )
      linkages =( Linkage [] )linkageList.toArray( ( new Linkage[ 0 ] ) );
    if( file != null ){
      Long size = new Long( file.length() );
      long mDate = file.lastModified();
      dataSize = new Integer( size.intValue() );
      if( mDate > 0L )
        modifiedDate = new Date( mDate );
    }
      
    return new IDMEF_File( file.getName(), 
			   file.getPath(), 
			   null, // createTime
			   modifiedDate, 
			   null, // accessTime
			   dataSize, // data size 
			   null, // disk size
			   fileAccesses, 
			   linkages, 
			   inode, 
			   category,
			   fstype, 
			   null ); // ident not necessary
  }

  /**
   * Factory method to create a FileAccess
   *
   * @param userId The user (or group) to which these permissions apply.
   *               The value of the "type" attribute must be "user-privs",
   *               "group-privs", or "other-privs" as appropriate.  Other
   *               values for "type" MUST NOT be used in this context.
   * @param permissionList Level of access allowed.  Recommended values are
   *                       "noAccess", "read", "write", "execute", "delete",
   *                       "executeAs", "changePermissions", and "takeOwnership".
   *                       The "changePermissions" and "takeOwnership" strings
   *                       represent those concepts in Windows.  On Unix, the
   *                       owner of the file always has "changePermissions"
   *                       access, even if no other access is allowed for
   *                       that user.  "Full Control" in Windows is represented
   *                       by enumerating the permissions it contains.  The
   *                       "executeAs" string represents the set-user-id and
   *                       set-group-id features in Unix.
   *
   * @return a FileAccess object
   */    
  public FileAccess createFileAccess( String userId, List permissionList ){
    String permissions[] = null;
    if( permissionList != null )
      permissions = ( String [] )permissionList.toArray( ( new String[ 0 ] ) );
    return new FileAccess( createUserId( userId ), permissions );
  }
    
  /**
   * Factory method to create a Linkage
   *
   * @param file the file that is linked to another file 
   * @param category The type of object that the link describes.  The 
   *                 permitted values are shown below.  There is no
   *                 default value.
   * <pre>
   * Rank   Keyword               Description
   * ----   -------               -----------
   *   0    Linkage.HARD_LINK     The <name> element represents another
   *                              name for this file.  This information
   *                              may be more easily obtainable on NTFS
   *                              file systems than others.
   *   1    Linkage.MOUNT_POINT   An alias for the directory specified by
   *                              the parent's <name> and <path> elements.
   *   2    Linkage.REPARSE_POINT Applies only to Windows; excludes
   *                              symbolic links and mount points, which
   *                              are specific types of reparse points.
   *   3    Linkage.SHORTCUT      The file represented by a Windows
   *                              "shortcut."  A shortcut is distinguished
   *                              from a symbolic link because of the
   *                              difference in their contents, which may
   *                              be of importance to the manager.
   *   4    Linkage.STREAM        An Alternate Data Stream (ADS) in
   *                              Windows; a fork on MacOS.  Separate file
   *                              system entity that is considered an
   *                              extension of the main <File>.
   *   5    Linkage.SYMBOLIC_LINK The <name> element represents the file
   *                              to which the link points.
   * </pre>
   * @return a Linkage object
   */  
  public Linkage createLinkage( File file, String category ){
    return new Linkage( file.getName(), file.getPath(), category );
  }
    
  /**
   * Factory method to create a Linkage
   *
   * @param file an IDMEF_File that is linked to another file 
   * @param category The type of object that the link describes.  The 
   *                 permitted values are shown below.  There is no
   *                 default value.
   * <pre>
   * Rank   Keyword               Description
   * ----   -------               -----------
   *   0    Linkage.HARD_LINK     The <name> element represents another
   *                              name for this file.  This information
   *                              may be more easily obtainable on NTFS
   *                              file systems than others.
   *   1    Linkage.MOUNT_POINT   An alias for the directory specified by
   *                              the parent's <name> and <path> elements.
   *   2    Linkage.REPARSE_POINT Applies only to Windows; excludes
   *                              symbolic links and mount points, which
   *                              are specific types of reparse points.
   *   3    Linkage.SHORTCUT      The file represented by a Windows
   *                              "shortcut."  A shortcut is distinguished
   *                              from a symbolic link because of the
   *                              difference in their contents, which may
   *                              be of importance to the manager.
   *   4    Linkage.STREAM        An Alternate Data Stream (ADS) in
   *                              Windows; a fork on MacOS.  Separate file
   *                              system entity that is considered an
   *                              extension of the main <File>.
   *   5    Linkage.SYMBOLIC_LINK The <name> element represents the file
   *                              to which the link points.
   * </pre>
   * @return a Linkage object
   */  
  public Linkage createLinkage( IDMEF_File file, String category ){
    return new Linkage( file, category );    
  }
    
  /**
   * Factory method to create an Inode (relevant to UNIX systems ONLY)
   *
   * @param changeTime The time of the last inode change.
   * @param number The inode number.
   * @param majorDevice The major device number of the device the
   *                    file resides on.
   * @param minorDevice The minor device number of the device the
   *                    file resides on.
   *
   * @return an Inode object
   */  
  public Inode createInode( Date changeTime, Integer number, 
			    Integer majorDevice, Integer minorDevice ){
    return new Inode( changeTime, number, majorDevice, minorDevice );
  }
    
  /**
   * Factory method to create an Inode (relevant to UNIX systems ONLY)
   *
   * @param changeTime The time of the last inode change.
   * @param cMajorDevice The major device of the file itself, if it
   *                     is a character special device.
   * @param cMinorDevice The minor device of the file itself, if it
   *                     is a character special device.
   *
   * @return an Inode object
   */  
  public Inode createInode( Date changeTime, Integer cMajorDevice, 
			    Integer cMinorDevice ){
    return new Inode( changeTime, cMajorDevice, cMinorDevice );
  }
    
  /**
   * Factory method to create a UserId
   *
   * @param aUser A user or group name.
   *
   * @return a UserId object
   */  
  public UserId createUserId( String aUser ){
    // user name and user identifier is the same in cougaar
    return new UserId( aUser, null, aUser, null );
  }   
    
  /**
   * Factory method to create an Address
   *
   * @param address The address information.  The format of
   *                this data is governed by the category attribute.
   * @param netMask The network mask for the address, if
   *                appropriate.
   * @param category The type of address represented.  The permitted values
   *                 for this attribute are shown below.  The default value
   *                 is "unknown".
   * <pre>
   * Rank   Keyword               Description
   * ----   -------               -----------
   *   0    Address.UNKNOWN       Address type unknown
   *   1    Address.ATM           Asynchronous Transfer Mode network
   *                              address
   *   2    Address.EMAIL         Electronic mail address (RFC 822)
   *   3    Address.LOTUS_NOTES   Lotus Notes e-mail address
   *   4    Address.MAC           Media Access Control (MAC) address
   *   5    Address.SNA           IBM Shared Network Architecture (SNA)
   *                              address
   *   6    Address.VM            IBM VM ("PROFS") e-mail address
   *   7    Address.IPV4_ADDR     IPv4 host address in dotted-decimal
   *                              notation (a.b.c.d)
   *   8    Address.IPV4_ADDR_HEX IPv4 host address in hexadecimal
   *                              notation
   *   9    Address.IPV4_NET      IPv4 network address in dotted-decimal
   *                              notation, slash, significant bits
   *                              (a.b.c.d/nn)
   *  10    Address.IPV4_NET_MASK IPv4 network address in dotted-decimal
   *                              notation, slash, network mask in dotted-
   *                              decimal notation (a.b.c.d/w.x.y.z)
   *  11    Address.IPV6_ADDR     IPv6 host address
   *  12    Address.IPV6_ADDR_HEX IPv6 host address in hexadecimal
   *                              notation
   *  13    Address.IPV6_NET      IPv6 network address, slash, significant
   *                              bits
   *  14    Address.IPV6_NET_MASK IPv6 network address, slash, network
   *                              mask
   *  99    Address.URL_ADDR      A url
   * </pre>
   * @return a Address object
   */  
  public Address createAddress( String address, 
				String netMask, 
				String category ){    
    return new Address( address, 
			netMask, 
			null, // unique id not necessary
			category, 
			null, // vlan-name not necessary 
			null );  // vlan-num not necessary
  }
    
  /**
   * Factory method to create an Impact
   *
   * All three attributes are optional.  The element itself may be empty,
   * or may contain a textual description of the impact, if the analyzer
   * is able to provide additional details.
 
   * @param severity An estimate of the relative severity of the event.  
   *                 The permitted values are shown below.  There is no
   *                 default value.
   * <pre>
   * Rank   Keyword            Description
   * ----   -------            -----------
   *   0    Impact.LOW         Low severity
   *   1    Impact.MEDIUM      Medium severity
   *   2    Impact.HIGH        High severity
   * </pre>
   * @param completion An indication of whether the analyzer believes the
   *                   attempt that the event describes was successful or not.
   *                   The permitted values are shown below.  There is no
   *                   default value.
   * <pre>
   * Rank   Keyword            Description
   * ----   -------            -----------
   *   0    Impact.FAILED      The attempt was not successful
   *   1    Impact.SUCCEEDED   The attempt succeeded
   * </pre>
   * @param type The type of attempt represented by this event, in relatively broad
   * categories.  The permitted values are shown below.  The default
   * value is "other."
   * <pre>
   * Rank   Keyword            Description
   * ----   -------            -----------
   *   0    Impact.ADMIN       Administrative privileges were
   *                           attempted or obtained
   *   1    Impact.DOS         A denial of service was attempted or
   *                           completed
   *   2    Impact.FILE        An action on a file was attempted or
   *                           completed
   *   3    Impact.RECON       A reconnaissance probe was attempted
   *                           or completed
   *   4    Impact.USER        User privileges were attempted or
   *                           obtained
   *   5    Impact.OTHER       Anything not in one of the above
   *                           categories
   * </pre>
   * @param description a description of the impact.
   *
   * @return a Impact object
   */   
  public Impact createImpact( String severity, 
			      String completion, 
			      String type,
			      String description ){
    return new Impact( severity, completion, type, description );
  }
    
  /**
   * Factory method to create an Action
   *
   * @param category The type of action taken.  The permitted values are
   *                 shown below.  The default value is "other."
   * <pre>
   * Rank   Keyword                   Description
   * ----   -------                   -----------
   *   0    Action.BLOCK_INSTALLED    A block of some sort was installed to
   *                                  prevent an attack from reaching its
   *                                  destination.  The block could be a port
   *                                  block, address block, etc., or disabling
   *                                  a user account.
   *   1    Action.NOTIFICATION_SENT  A notification message of some sort was
   *                                  sent out-of-band (via pager, e-mail,
   *                                  etc.).  Does not include the
   *                                  transmission of this alert.
   *   2    Action.TAKEN_OFFLINE      A system, computer, or user was taken
   *                                  offline, as when the computer is shut
   *                                  down or a user is logged off.
   *   3    Action.OTHER              Anything not in one of the above
   *                                  categories.
   * </pre>
   * @param description a description of the action
   *
   * @return a Action object
   */  
  public Action createAction( String category, String description ){
    return new Action( category, description );
  }
    
  /**
   * Factory method to create a Confidence
   *
   * @param rating The analyzer's rating of its analytical validity.
   *               <br>Permitted values:<br>
   *                  <code>Confidence.LOW, Confidence.MEDIUM, 
   *                  Confidence.HIGH, Confidence.NUMERIC</code>
   * @param numeric if the rating is Confidence.NUMERIC, set numeric to 
   *                a Float object between 0.0 and 1.0., null otherwise.
   *
   * @return a Confidence object
   */  
  public Confidence createConfidence( String rating, Float numeric ){
    return new Confidence( rating, numeric );
  }

  /**
   * Creates a new Agent that references an analyzer, source, or
   * target.
   * 
   * @param name the name of the agent
   * @param description a description of the agent
   * @param location descriptive location of the agent (e.g., Santa Clara, CA)
   * @param address a url Address of this agent
   * @param refIdentList a list of analyzer, source, or target identifiers
   *                     this agent references.
   * 
   * @return a new Agent
   */    
  public Agent createAgent( String name, 
                            String description, 
		                        String location, 
		                        Address address, 
		                        List refIdentList ){
		                          
    String refIdents[] = null;
    if( refIdentList != null )
      refIdents = ( String [] )refIdentList.toArray( ( new String[ 0 ] ) );
    return new Agent( name, description, location,
		      address, refIdents );                
  }
        
  /** 
   * Get the Agent object that this message factory belongs to
   *
   * @return an Agent object
   */
  public Agent getAgentInfo(){
    return m_agent;
  }
  
  /** 
   * Get the Process object that this message factory belongs to
   *
   * @return an IDMEF_Process object
   */
  public IDMEF_Process getProcessInfo(){
    return m_process;
  }
  
  /** 
   * Get the Node object that this message factory belongs to
   *
   * @return an IDMEF_Node object
   */
  public IDMEF_Node getNodeInfo(){
    return m_node;
  }
  /** 
   * Get the User name that this message factory is running under
   *
   * @return an User object
   */
  public User getUserInfo(){
    return m_user;
  }
  
  /**
   * Factory method to create a unique id from the UIDServer
   *
   * @return a unique String id
   */      
  public String createUniqueId(){
    // delegate to some global unique id generator
    String uid = null;
    if(m_uidServer != null) {
      uid = m_uidServer.nextUID().toString();
    }
    return uid;
  }
    
  // Need for Analyzer information as per IDMEF v1.0 draft
  private String m_osName;
  private String m_osVersion;
    
  private static String PROCESS_NAME = "org.cougaar.core.node.Node";
    
  private Agent m_agent;
  private IdmefMessageFactory m_idmefMessageFactory;
  // agent information 
  // there is only one IdmefMessageFactory per Cougaar Agent
  private AdditionalData m_agentData;
  private MessageAddress m_agentId;
  private UIDServer m_uidServer;
  private IDMEF_Process m_process;
  private IDMEF_Node m_node;
  private LDMServesPlugin m_ldm;
  private User m_user;
    
}
