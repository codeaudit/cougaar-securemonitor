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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class is just a bunch of static methods for use with common file input operations. 
 * It should be considered beta level software. 
 */
public class FileUtils{
 /** 
  * This method is used to read a line in from an input stream into a string.
  * For testing purposes only! Use at your own risk!
  * @param in the InputStream to read in from.
  * @return the string that was read in*/
  public static String getNextLine(InputStream in) throws IOException{
	  StringBuffer s = new StringBuffer();
	  int next=0;
	  try{
	    next = in.read();
	  }
    catch (IOException e) {
      e.printStackTrace();
    }
	  if (next == '\n' || next == -1) 
      return new String();
	  while (next != '\n' && next != -1){
	    s.append( (char) next);
	    try{
		    next = in.read();
	    }
      catch (IOException e) {
        e.printStackTrace();
      }
	  }
	  return s.toString().trim();
  }
 /** 
  * This method is used to read a file into a string.
  * For testing purposes only! Use at your own risk!
  * @param fileName name of a file to read in from.
  * @return the string that was read in
  */
  public static String readWholeFile(String fileName)throws IOException{
	  FileReader in = new FileReader(fileName);
  	return readWholeFile(in);
  }
  
  /** 
   * This method is used to read a file into a string.
   * For testing purposes only! Use at your own risk!
   * @param file the File to read in from.
   * @return the string that was read in
   */
  public static String readWholeFile(File file)throws IOException{
	  FileReader in = new FileReader(file);
	  return readWholeFile(in);
  }
  /** 
   * This method is used to read a file into a string.
   * For testing purposes only! Use at your own risk!
   * @param in the FileReader to read in from.
   * @return the string that was read in
   */
  public static String readWholeFile(FileReader in)throws IOException{
	  int next;
	  StringBuffer fileString = new StringBuffer();
	  while ((next = in.read()) != -1)
	    fileString.append((char)next);
	  return fileString.toString();
  }
}
