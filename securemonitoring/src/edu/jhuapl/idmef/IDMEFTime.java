/* The following passage applies to all software and text files in this distribution, 
including this one:

Copyright (c) 2001, Submarine Technology Department, The Johns Hopkins University 
Applied Physics Laboratory.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, 
are permitted provided that the following conditions are met:

    -> Redistributions of source code must retain the above copyright notice, 
       this list of conditions and the following disclaimer.

    -> Redistributions in binary form must reproduce the above copyright notice, 
       this list of conditions and the following disclaimer in the documentation 
       and/or other materials provided with the distribution.

    -> Neither the name of the Johns Hopkins University Applied Physics Laboratory
       nor the names of its contributors may be used to endorse or promote products 
       derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR 
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
OF SUCH DAMAGE.
*/

package edu.jhuapl.idmef;

import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/** 
 * This class is a superclass of all the IDMEF Time classes (since they are so similar).
 */
public class IDMEFTime implements XMLSerializable {
    
    private String idmefDate;
    private String ntpstamp;

    protected static final String ATTRIBUTE_NTPSTAMP = "ntpstamp";
    public static final String ELEMENT_NAME = "IDMEFTime";
    
    public static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    /**
     * This method creates a new IDMEFTime set to the current time.
     */
    public IDMEFTime(){
	    Date date = new Date();
      idmefDate = convertToIDMEFFormat(date);
      ntpstamp = convertToNTP(date);
    }
  
    /**
     * This method creates a new IDMEFTime set to any date.
     */
    public IDMEFTime(Date inDate){
	    idmefDate = convertToIDMEFFormat(inDate);
      ntpstamp = convertToNTP(inDate);
    }

    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public IDMEFTime (Node node){
	    idmefDate = XMLUtils.getAssociatedString(node);
	    NamedNodeMap nnm = node.getAttributes();
	    Node ntpNode = nnm.getNamedItem(ATTRIBUTE_NTPSTAMP);
	    ntpstamp = ntpNode.getNodeValue();
    }

    /** 
     * Converts a Date to the IDMEF Date format. Currently only does Zulu time (UTC)
     */
    public static String convertToIDMEFFormat(Date date){
      SimpleDateFormat formatter = new SimpleDateFormat (DATE_FORMAT);
    	return formatter.format(date);
    }
    
    /** 
     * Converts a Date to the NTP format. 
     */
    public static String convertToNTP(Date date){
      SimpleDateFormat formatter = new SimpleDateFormat ("'.0x'SSS'00000'");
	    String currentSecs = (new Long(  (date.getTime())/1000 ).toString());
	    BigInteger seconds = new BigInteger("2208988800").add(new BigInteger(currentSecs));
	    return "0x" + seconds.toString(16) + formatter.format(date);
    }
    
    public String getidmefDate(){
	    return idmefDate;

    }
    public void setIdmefDate(Date inDate){
      idmefDate = convertToIDMEFFormat(inDate);
    }

    public String getNtpstamp(){
	    return ntpstamp;

    }
    public void setNtpstamp(Date inDate){
	    ntpstamp = convertToNTP(inDate);
    }

    public Node convertToXML(Document parent){
	    Element timeNode = parent.createElement(ELEMENT_NAME);
	    timeNode.setAttribute(ATTRIBUTE_NTPSTAMP, getNtpstamp());
	    timeNode.appendChild(parent.createTextNode(getidmefDate()));
	    return timeNode;
    }
}
