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


package org.cougaar.core.security.monitoring.blackboard;

import org.cougaar.core.component.ServiceBroker;
import org.cougaar.core.domain.Factory;
import org.cougaar.core.mts.MessageAddress;
import org.cougaar.core.security.monitoring.idmef.IdmefMessageFactory;
import org.cougaar.core.service.UIDServer;
import org.cougaar.core.util.UID;
import org.cougaar.planning.ldm.LDMServesPlugin;
import org.cougaar.planning.ldm.PlanningFactory;
import org.cougaar.planning.ldm.asset.Asset;

import edu.jhuapl.idmef.IDMEF_Message;

public class CmrFactory
implements Factory
{
  protected MessageAddress selfClusterId;
  protected UIDServer myUIDServer;
  private  IdmefMessageFactory idmefmessagefactory;

  private ServiceBroker serviceBroker;

  /**
   * Constructor for use by domain specific Factories
   * extending this class
   */
  public CmrFactory() { }
  // change the input parameter to an agent id service and uid service or just service broker
  public CmrFactory(LDMServesPlugin ldm) {
    // Attach our factory to the M&R factory
    PlanningFactory pf = ldm.getFactory();
	
    /*
      See org.cougaar.tools.csmart.runtime.ldm.CSMARTFactory for
      an example of what to add here.
      pf.addAssetFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.AssetFactory());
      pf.addPropertyGroupFactory(
      new org.cougaar.tools.csmart.runtime.ldm.asset.PropertyGroupFactory());
    */
    selfClusterId = ldm.getMessageAddress();
    myUIDServer = ldm.getUIDServer();
    idmefmessagefactory=new IdmefMessageFactory(ldm);

  }
  
  /**
   * @return a new <code>UID</code>
   */
  public UID getNextUID() {
    return myUIDServer.nextUID();
  }

  public NewEvent newEvent(IDMEF_Message aMessage) {
    return new EventImpl(getNextUID(),
                         selfClusterId,
                         aMessage);
  }
  
  public ConsolidatedEvent newConsolidatedEvent(MessageAddress source,IDMEF_Message aMessage) {
    return new ConsolidatedEventImpl(source,aMessage);
  }
  public ConsolidatedEvent newConsolidatedEvent(ConsolidatedEvent event ) {
    return new ConsolidatedEventImpl(event.getSource(),event.getEvent());
  }
   public ConsolidatedEvent newConsolidatedEvent(RemoteConsolidatedEvent event ) {
    return new ConsolidatedEventImpl(event.getSource(),event.getEvent());
  }
 
  public NewEventTransfer newEventTransfer(Event event,
                                           Asset target) {
    return new EventTransferImpl(getNextUID(),
                                 target,
                                 event);
  }
  public IdmefMessageFactory getIdmefMessageFactory(){
    return idmefmessagefactory;
  }
    
  public CmrRelay newCmrRelay(Event event, MessageAddress dest) {
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, event, null);
    return relay;
  }
  
  public CmrRelay newCmrRelay(Object event, MessageAddress dest) {
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, event,null);
    return relay;
  }
 
  /** Creates a new CmrRelay object containing a DrillDownQuery object
   * @param query    The query set by the user in the security console
   * @param aggType  The type of aggregation (e.g. how aggregation is performed)
   * @param wantDetails 
   * @param dest     The target of the query
   */
  /*
    This method is currently commented as there is a bug in the Agg Query mechanism 
    till then we will use the following method
    public CmrRelay newDrillDownQueryRelay(String query,
    AggregationType aggType,
    boolean wantDetails,
    MessageAddress dest)

    public CmrRelay newDrillDownQueryRelay(AggregationQuery query,
    AggregationType aggType,
    boolean wantDetails,
    MessageAddress dest) {
    AggregationDrillDownQuery aggquery=new AggregationDrillDownQuery(query ,aggType);
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, aggquery, null);
    return relay;
    
    }
  */
  public CmrRelay newDrillDownQueryRelay(UID originatorUID,String query,
					 AggregationType aggType,
					 boolean wantDetails,
					 MessageAddress dest) {
    AggregationDrillDownQuery aggquery=new AggregationDrillDownQuery(originatorUID,query ,aggType);
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, aggquery, null);
    return relay;
    
  }
  public CmrRelay newDrillDownQueryRelay(String query,
					 AggregationType aggType,
					 boolean wantDetails,
					 MessageAddress dest) {
    AggregationDrillDownQuery aggquery=new AggregationDrillDownQuery(query ,aggType);
    CmrRelay relay = new CmrRelay(getNextUID(), selfClusterId, dest, aggquery, null);
    return relay;
    
  }
}
