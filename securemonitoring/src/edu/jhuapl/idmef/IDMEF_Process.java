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

import java.util.ArrayList;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** 
 * <pre>
 *  The Process class is used to describe processes being executed on
 *  sources, targets, and analyzers.
 *
 *  The Process class is composed of five aggregate classes, as shown in
 *  Figure 4.17.
 *
 *                 +--------------+
 *                 |    Process   |
 *                 +--------------+            +------+
 *                 | STRING ident |<>----------| name |
 *                 |              |            +------+
 *                 |              |       0..1 +------+
 *                 |              |<>----------| pid  |
 *                 |              |            +------+
 *                 |              |       0..1 +------+
 *                 |              |<>----------| path |
 *                 |              |            +------+
 *                 |              |       0..* +------+
 *                 |              |<>----------| arg  |
 *                 |              |            +------+
 *                 |              |       0..* +------+
 *                 |              |<>----------| env  |
 *                 |              |            +------+
 *                 +--------------+
 *
 *                    Figure 4.17 - The Process Class
 *
 *  The aggregate classes that make up Process are:
 *
 *  name
 *     Exactly one.  STRING.  The name of the program being executed.
 *     This is a short name; path and argument information are provided
 *     elsewhere.
 *
 *  pid
 *     Zero or one.  INTEGER.  The process identifier of the process.
 *
 *  path
 *     Zero or one.  STRING.  The full path of the program being
 *     executed.
 *
 *  arg
 *     Zero or more.  STRING.  A command-line argument to the program.
 *     Multiple arguments may be specified (they are assumed to have
 *     occurred in the same order they are provided) with multiple uses
 *     of arg.
 *
 *  env
 *     Zero or more.  STRING.  An environment string associated with the
 *     process; generally of the format "VARIABLE=value".  Multiple
 *     environment strings may be specified with multiple uses of env.
 *
 *  This is represented in the XML DTD as follows:
 *
 *     &lt!ELEMENT Process                       (
 *         name, pid?, path?, arg*, env*
 *      )&gt
 *     &lt!ATTLIST Process
 *         ident               CDATA                   '0'
 *     &gt
 *
 *  The Process class has one attribute:
 *
 *  ident
 *     Optional.  A unique identifier for the process.
 *
 * </pre>
 * <p>See also the <a href='http://search.ietf.org/internet-drafts/draft-ietf-idwg-idmef-xml-07.txt'>IETF IDMEF Draft Specification v0.7</a>.
 */
public class IDMEF_Process implements XMLSerializable{

  private String name;    
  private Integer pid;
  private String path;
  private String args[];
  private String envs[];

  //attributes
  private String ident;
  // child element names
  private static final String CHILD_ELEMENT_NAME = "name";
  private static final String CHILD_ELEMENT_PID = "pid";
  private static final String CHILD_ELEMENT_PATH = "path";
  private static final String CHILD_ELEMENT_ARG = "arg";
  private static final String CHILD_ELEMENT_ENV = "env";
  
  public static final String ELEMENT_NAME = "Process";

  //getters and setters
  public String getName(){
    return name;
  }
  public void setName(String inName){
    name = inName;
  }

  public Integer getPid(){
    return pid;
  }
  public void setPid(Integer inPid){
    pid = inPid;
  }


  public String getPath(){
    return path;
  }
  public void setPath(String inPath){
    path = inPath;
  }


  public String[] getArgs(){
    return args;
  }
  public void setArgs(String[] inArgs){
    args = inArgs;
  }


  public String[] getEnvs(){
    return envs;
  }
  public void setEnvs(String[] inEnvs){
    envs = inEnvs;
  }


  public String getIdent(){
    return ident;
  }
  public void setIdent(String inIdent){
    ident = inIdent;
  }
  /**
   * Example of an equals method.
   * <pre> 
   * returns true when attributes of comparing object and this object are null or equal.
   * Attributes that are compared are :
   *  Name
   *  Path 
   * <b>
   * NOTE: This is specific to how systems use IDMEF messages and
   *       what it means when two objects are equivalent.  For
   *       example, equivalence may mean a subset of the objects
   *       attributes.  It's advised that this method is modified
   *       for your particular environment.
   * </b>
   * </pre> 
   */
  public boolean equals(Object anObject) {
    boolean equals=false;
    boolean arenameequal=false;
    boolean arepidequal=true;
    boolean arepathequal=false;
    boolean areargsequal=true;
    boolean areenvsequal=true;
    IDMEF_Process process;
    if(anObject==null) {
      return equals;
    }
    if( anObject instanceof IDMEF_Process) {
      process=( IDMEF_Process)anObject;
      String myvalue;
      String invalue;
      myvalue=this.getName();
      invalue=process.getName();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arenameequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arenameequal=true;
      }
      myvalue=this.getPath();
      invalue=process.getPath();
      if( (myvalue!=null) && (invalue!=null) ) {
	      if(myvalue.trim().equals(invalue.trim())) {
	        arepathequal=true;
	      }
      }
      else if((myvalue==null) && (invalue==null)) {
	      arepathequal=true;
      }
      /*
      String [] myarray;
      String [] inarray;
      myarray=this.getArgs();
      inarray=process.getArgs();
      if((myarray!=null)&&(inarray!=null)) {
	if(myarray.length==inarray.length) {
	  String value;
	  for(int i=0;i<inarray.length;i++) {
	    value=inarray[i];
	    if(!contains(myarray,value)) {
	      areargsequal=false;
	      break;
	    }
	  }
	  areargsequal=true;
	}
      }
      else if((myarray==null) && (inarray==null)) {
	areargsequal=true;
      }
      
      myarray=this.getEnvs();
      inarray=process.getEnvs();
      if((myarray!=null)&&(inarray!=null)) {
	if(myarray.length==inarray.length) {
	  String value;
	  for(int i=0;i<inarray.length;i++) {
	    value=inarray[i];
	    if(!contains(myarray,value)) {
	      areenvsequal=false;
	      break;
	    }
	  }
	  areenvsequal=true;
	}
      }
      else if((myarray==null) && (inarray==null)) {
	areenvsequal=true;
      }
      if((this.getPid()!=null) && (process.getPid()!=null)) {
	if(this.getPid().equals(process.getPid())) {
	  arepidequal=true;
	}
      }
      else if((this.getPid()==null) && (process.getPid()==null)) {
	arepidequal=true;
      }
      */
      if(arenameequal && arepathequal && areargsequal && areenvsequal && arepidequal) {
	      equals=true;
      }
    }
    return equals;
  }

  public boolean contains(String [] container, String inString) {
    boolean contains=false;
    if(container==null) {
      return contains;
    }
    String compstring;
    for(int i=0;i<container.length;i++) {
      compstring=container[i];
      if(compstring.trim().equals(inString.trim())) {
	      contains=true;
	      return contains;
      }
      
    }
    return contains;
  } 
  /**
   * Creates an object with all fields null.
   */
  public IDMEF_Process(){
    this(null, null, null, null, null, null);
  }
  
  /**
   * Copies arguments into corresponding fields.
   */
  public IDMEF_Process(String inName, Integer inPid, String inPath,
		       String inArgs[], String inEnvs[], String inIdent){

    name = inName;
    pid = inPid;
    path = inPath;
    args = inArgs;
    envs = inEnvs;
    ident= inIdent;
  }

  /**
   * Creates an object from the XML Node containing the XML version of this object.
   * This method will look for the appropriate tags to fill in the fields. If it cannot find
   * a tag for a particular field, it will remain null.
   */
  public IDMEF_Process (Node node){

    Node nameNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_NAME);
    if (nameNode == null) name = null;
    else name = XMLUtils.getAssociatedString(nameNode);

    Node pidNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_PID);
    if (pidNode == null) pid = null;
    else pid = new Integer(XMLUtils.getAssociatedString(pidNode));

    Node pathNode =  XMLUtils.GetNodeForName(node, CHILD_ELEMENT_PATH);
    if (pathNode == null) path = null;
    else path = XMLUtils.getAssociatedString(pathNode);


    //get address nodes here
    NodeList children = node.getChildNodes();
    ArrayList argNodes = new ArrayList();
    ArrayList envNodes = new ArrayList();
    for (int i=0; i<children.getLength(); i++){
      Node finger = children.item(i);
      if (finger.getNodeName().equals(CHILD_ELEMENT_ARG)){
	      String newArg = XMLUtils.getAssociatedString(finger);
	      argNodes.add(newArg);
      } 
      else if (finger.getNodeName().equals(CHILD_ELEMENT_ENV)){
	      String newEnv = XMLUtils.getAssociatedString(finger);
  	    envNodes.add(newEnv);
      }
    }
    args = new String[argNodes.size()];
    for (int i=0; i< argNodes.size(); i++){
      args[i] = (String) argNodes.get(i);
    }
    envs = new String[envNodes.size()];
    for (int i=0; i< envNodes.size(); i++){
      envs[i] = (String) envNodes.get(i);
    }

    NamedNodeMap nnm = node.getAttributes();

    Node identNode = nnm.getNamedItem(ATTRIBUTE_IDENT);
    if(identNode == null) ident=null;
    else ident = identNode.getNodeValue();

  }
  public Node convertToXML(Document parent){

    Element processNode = parent.createElement(ELEMENT_NAME);
    if(ident != null)
      processNode.setAttribute(ATTRIBUTE_IDENT, ident);

    if(name != null){
      Node nameNode = parent.createElement(CHILD_ELEMENT_NAME);
      nameNode.appendChild(parent.createTextNode(name));
      processNode.appendChild(nameNode);
	    
    }

    if(pid != null){
      Node pidNode = parent.createElement(CHILD_ELEMENT_PID);
      pidNode.appendChild(parent.createTextNode(pid.toString()));
      processNode.appendChild(pidNode);
	    
    }

    if(path != null){
      Node pathNode = parent.createElement(CHILD_ELEMENT_PATH);
      pathNode.appendChild(parent.createTextNode(path));
      processNode.appendChild(pathNode);
	    
    }


    if (args != null){
      for (int i=0; i<args.length; i++){
	      Node argNode = parent.createElement(CHILD_ELEMENT_ARG);
	      argNode.appendChild(parent.createTextNode(args[i]));
	      processNode.appendChild(argNode);
      }
    }
    if (envs != null){
      for (int i=0; i<envs.length; i++){
	      Node envNode = parent.createElement(CHILD_ELEMENT_ENV);
	      envNode.appendChild(parent.createTextNode(envs[i]));
	      processNode.appendChild(envNode);
      }
    }

    return processNode;
  }
}
