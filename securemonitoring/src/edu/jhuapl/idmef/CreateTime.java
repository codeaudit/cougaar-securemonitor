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

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/** 
 * <pre>
 *  The CreateTime class is used to indicate the date and time the alert
 *  or heartbeat was created by the analyzer.  It is represented in the
 *  XML DTD as follows:
 *
 *     &lt!ELEMENT CreateTime          (#PCDATA) &gt
 *     &lt!ATTLIST CreateTime
 *         ntpstamp            CDATA                   #REQUIRED
 *     &gt
 *
 *  The DATETIME format of the <CreateTime> element content is described
 *  in Section 3.4.6 of the IDMEF specification draft v0.7.
 *
 *  The CreateTime class has one attribute:
 *
 *  ntpstamp
 *     Required.  The NTP timestamp representing the same date and time
 *     as the element content.  The NTPSTAMP format of this attribute's
 *     value is described in Section 3.4.7 in the draft.
 *
 *  If the date and time represented by the element content and the NTP
 *  timestamp differ (should "never" happen), the value in the NTP
 *  timestamp MUST be used.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Specification Draft v0.7 </a>.
 */
public class CreateTime extends IDMEFTime{
    public static final String ELEMENT_NAME = "CreateTime";
    
    /**
     * This constructor creates a CreateTime with the current time
     */
    public CreateTime (){
	    super();
    }
    /**
     * Creates an object from the XML Node containing the XML version of this object.
     * This method will look for the appropriate tags to fill in the fields. If it cannot find
     * a tag for a particular field, it will remain null.
     */
    public CreateTime (Node node){
	    super(node);
    }

    public Node convertToXML(Document parent){
	    Element timeNode = parent.createElement(ELEMENT_NAME);
	    timeNode.setAttribute(ATTRIBUTE_NTPSTAMP, getNtpstamp());
	    timeNode.appendChild(parent.createTextNode(getidmefDate()));
	    return timeNode;
    }
}
