/* DATA_mapping.sc

   This script provides Java annotation driven data mapping report that
   allows the user to finely track certain annotated data objects in their
   code all the way to sinks such as NETWORK, LOG, FILE or EMAIL. For the 
   script to work, the user has to supply the java annotation string used in
   their application (such as @SensitiveBeacon)

   Version: 0.0.1
   Ocular Version: 0.3.70
   Author: Chetan Conikee <chetan@shiftLeft.io>
   Input: Application JAR/WAR/EAR, Tracking Java annotation string
   Output: JSON

 */

import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`
import $ivy.`io.circe::circe-optics:0.10.0`

import io.circe.parser
import io.circe.generic.semiauto.deriveDecoder
import io.circe.generic.auto._
import io.circe.parser._, io.circe.syntax._
import io.circe.Json
import cats.syntax.either._
import io.circe.optics.JsonPath._

import $file.^.java.utils.taint_tags
import $file.^.java.utils.traces
import $file.^.java.utils.token_patterns
import $file.^.java.utils.data

// Report title and description
val title = "[DATA] Annotation Based Data Mapping Report (Use cases : CCPA, GDPR, SOC-1/2)"
val description = "Right now, protecting data can be difficult. It’s often spread across and copied to a number of different environments, and it’s hard to know what to restrict it to and where it’s located. This data sprawl inevitably leaves organizations open to data breaches, and not just from hackers either. In its 2017 end of year review of data breaches, the Identity Theft Resource Center revealed that ~10% of breaches were caused by employee error or negligence, ~7% were a result of accidental exposure, and ~5% were down to insider theft. Using annotation as a tracking beacon, this report plots all pathways of objects representing PII data from inside the application to outbound channels (FILESYSTE, NETWORK, LOGGER, etc)"
val recommendation="Idenitify data flow semantics of all annotated data elements. Verify if every user defined type inherits from a base model with appropriate controls in place." 

// Script help and usage text
val usage = """The Annotation Based Data Mapping script a map of custom java annotation 
based tracked data highlighting the tracked members, their classes, information whether 
they belong to a standard data model as well as information about where the data sinks 
to (such as network, log, etc.). The user is required to input the jar and the custom
java annotation used (such as @SensitiveBeacon) used to track the specific data objects. 

Running the Script
------------------

    $ ./ocular.sh --script /path/to/DATA_mapping.sc \
                --command execute \
                --params jarFile=/path/to/test.jar,outFile=data_mapping_redact.json

As seen above, the script takes two parameters:

    - jarFile : he path of the jar/war/ear java/scala artifact to analyze
    - outFile : The report output in JSON format
    - tracingBeacon : The java annotation string in @<Annotation> format used to track data 

The JSON report generated has the following keys:

    "name": The java annotation string (such as @SensitiveData) used to track data
    "modelName": The class name containing the sensitive members
    "members": Array of sensitive members annotated with the given java annotation 
    "baseTypes": Array base classes from which the model derives from (Useful to check conformity to a business defined data model)
    "isToStringOverridden": check if toString() method is overridden by the sensitive class
    "sinkChannels": Channels such as NETWORK, LOGGER, FILE and EMAIL to which tracked data goes
      |_ "isSinkingTo": True or False for either of channels above
      |_ "sinkMethod": sink method of either of the sink channel types to which track data goes

Sample Output
-------------

    {
        "name" : "@SensitiveRedact",
        "modelName" : "io.shiftleft.tarpit.model.Order",
        "members" : [
            "creditCardNumber"
        ],
        "baseTypes" : [
            "Object"
        ],
        "isToStringOverriden" : true,
        "sinkChannels" : {
            "NETWORK" : {
                "isSinkingTo" : true,
                "sinkMethod" : "java.io.PrintWriter.println:void(java.lang.String)"
            },
            "LOGGER" : {
                "isSinkingTo" : true,
                "sinkMethod" : "java.util.logging.Logger.info:void(java.lang.String)"
            },
            "FILE" : {
                "isSinkingTo" : false,
                "sinkMethod" : null
            },
            "EMAIL" : {
                "isSinkingTo" : true,
                "sinkMethod" : "javax.mail.Transport.send:void(javax.mail.Message)"
            }
        }
    }
"""

case class SinkInfo(isSinkingTo: Boolean, sinkMethod : Option[String])
case class AnnotatedModel(name : String , 
                          modelName : String, 
                          members : List[String], 
                          baseTypes : List[String], 
                          isToStringOverriden : Boolean, 
                          sinkChannels : Map[String, SinkInfo])
case class Result(title : String, description : String, recommendation : String, annotatedModels : List[AnnotatedModel])

def isSinkingInto(cpg: io.shiftleft.codepropertygraph.Cpg, sinkList : List[String], model : String) = {
    sinkList.map {
      sinkType =>
         val source = cpg.local.evalType(model).referencingIdentifiers
         val sink = cpg.method.fullName(taint_tags.sinks(sinkType)).parameter
         val flows = sink.reachableBy(source).flows
         val sinkMethod = flows.sink.l.map(_.method.fullName).headOption
         val isSink = sinkMethod match {
            case Some(s) => true
            case None => false
         }
         (sinkType,SinkInfo(isSink, sinkMethod))
    }.toMap
}

def getAnnotatedModels(cpg: io.shiftleft.codepropertygraph.Cpg, annotationType : String) = {
    val annotatedModels = cpg.annotation.code(annotationType).member.l.map {
        i => (i.name, i.start.typeDecl.fullName.head)
    } groupBy(_._2) map { case(k,v) => 
        AnnotatedModel(annotationType,
                        k,
                        v.map(_._1),
                        cpg.typeDecl.fullName(k).baseTypeDecl.name.l ,
                        cpg.types.fullName(k).method.name.l.filter(_.contains("toString")).size>0,
                        isSinkingInto(cpg,List("NETWORK","LOGGER","FILE","EMAIL"),k)) 
    }
    Result(title, description, recommendation, annotatedModels.toList).asJson.spaces2
}

// datamapping.getAnnotatedModels(cpg, "@SensitiveRedact")
// datamapping.getAnnotatedModels(cpg, "@SensitiveBeacon")


def createResults(jarFile: String, dirPath: String, tracingBeacon : String) = {
    val dataMappingFile = dirPath + java.io.File.separator + "DATA_mapping.json"
    val writer = new java.io.PrintWriter(new java.io.File(dataMappingFile))
    writer.write(getAnnotatedModels(cpg, tracingBeacon))
    writer.close()
    dataMappingFile
}


@doc(description)
@main def execute(jarFile: String, 
                outFile: String,
                tracingBeacon : String) : Boolean = {
    
    println("[+] Verify if CPG exists") 
    if(!workspace.baseCpgExists(jarFile)) {

        println("[+] Creating CPG and SP for " + jarFile) 
        createCpgAndSp(jarFile)

        println("[+] Verify if CPG was created successfully") 
        if(!workspace.baseCpgExists(jarFile)) {
            println("Failed to create CPG for " + jarFile)
            return false
        }
    } else {
        println("[+] Loading pre-existing CPG")
        loadCpg(jarFile)
    }
    
    println("[+] Check if CPG is loaded")
    if(workspace.loadedCpgs.toList.size == 0) {
        println("Failed to load CPG for " + jarFile)
        return false
    } else {
        println("Writing to OutFile : " + outFile)
        val writer = new java.io.PrintWriter(new java.io.File(outFile))
        writer.write(getAnnotatedModels(cpg, tracingBeacon))
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    } 
}