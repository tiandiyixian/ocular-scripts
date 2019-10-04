/* DATA_mapping.sc

   Version: 0.0.1
   Ocular Version: 0.3.70
   Author: Chetan Conikee <chetan@shiftLeft.io>
   Input: Application JAR/WAR/EAR
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

case class SinkInfo(isSinkingTo: Boolean, sinkMethod : Option[String])
case class AnnotatedModel(name : String , modelName : String, members : List[String], baseTypes : List[String], isToStringOverriden : Boolean, sinkChannels : Map[String, SinkInfo])

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
    } groupBy(_._2) map { case(k,v) => AnnotatedModel(annotationType,
    k,
    v.map(_._1),
    cpg.typeDecl.fullName(k).baseTypeDecl.name.l ,
    cpg.types.fullName(k).method.name.l.filter(_.contains("toString")).size>0,
    isSinkingInto(cpg,List("NETWORK","LOGGER","FILE","EMAIL"),k)) }
    annotatedModels.asJson.spaces2
}

// datamapping.getAnnotatedModels(cpg, "@SensitiveRedact")
// datamapping.getAnnotatedModels(cpg, "@SensitiveBeacon")

 @doc("")
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