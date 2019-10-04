/* SCA_bom
 *
 * Version: 0.0.1
 * Ocular Version: 0.3.70
 * Author: Chetan Conikee <chetan@shiftLeft.io>
 * Input: Application CPG
 * Output: JSON
 * 
 * Description: 
 * 
 */

import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`
import $ivy.`io.circe::circe-optics:0.10.0`

import $ivy.`com.lihaoyi::requests:0.1.7`
import $ivy.`org.json4s::json4s-jackson:3.6.5`
import $ivy.`org.apache.commons:commons-lang3:3.0`
import $ivy.`org.apache.maven:maven-artifact:3.6.1`

// JSON utilities, cursors and decoders 
import io.circe.parser
import io.circe.generic.semiauto.deriveDecoder
import io.circe.generic.auto._
import io.circe.parser._, io.circe.syntax._
import io.circe.Json
import cats.syntax.either._
import io.circe.optics.JsonPath._

import org.apache.commons.lang3.StringUtils

// Report title and description
val title = "[SCA] Software Composition Analysis"
val description = "The SCA BOM script provides monitoring of the libraries you use in your Java project to identify the use of known vulnerable components"
val recommendation="Based on CVE advisory upgrade components with known vulnerabilities and active CVEs"

case class BOM(groupId : String, artifactId : String, version : String)
case class BOMCVE(groupId : String, artifactId : String, version : String, cves : Json)

case class Result(title : String, description : String, recommendation : String, dependencies : List[BOMCVE])

implicit val recordsDecoder = deriveDecoder[BOMCVE]

def getBOM(cpg: io.shiftleft.codepropertygraph.Cpg) : List[BOM] = {
        cpg.dependency.l.map { d =>
                (d.dependencyGroupId, d.name, d.version) 
        } filter { d =>
                !d._3.equals("unknown") && !d._1.equals(None) } map { 
                d => BOM(d._1.get, d._2, d._3) 
        } distinct
}

def getCVEsForBOM(cpg: io.shiftleft.codepropertygraph.Cpg, ossIndexUri : String, ossAuthToken : String) = {
        
        val bomList = getBOM(cpg)

        val bomCVEList = bomList map { bom => 
                
                val groupId = bom.groupId
                val artifactId = bom.artifactId
                val version = bom.version

                val headersData = Map("accept" -> "application/vnd.ossindex.component-report.v1+json", 
                        "authorization" -> s"Basic ${ossAuthToken}", 
                        "Content-Type" -> "application/vnd.ossindex.component-report-request.v1+json")
                
                val body = s"""{ "coordinates" : [ "pkg:maven/$groupId/$artifactId@$version" ]}"""

                printf(" Processing Coordinates %s\n", body)       

                val cveRequest = requests.post(ossIndexUri, headers = headersData, data = body)
                
                val result = if(cveRequest.statusCode == 200) {
                        parser.parse(cveRequest.text).getOrElse(Json.Null)
                } else {
                        Json.Null
                }

                BOMCVE(groupId, artifactId, version, result)
        } 
        
        Result(title, 
                description,
                recommendation, 
                bomCVEList).asJson.spaces2

}

def createResults(jarFile: String, ossIndexUri : String, ossAuthToken : String, dirPath: String) = {
    val bom = dirPath + java.io.File.separator + "SCA_bom.json"
    val writer = new java.io.PrintWriter(new java.io.File(bom))
    writer.write(getCVEsForBOM(cpg, ossIndexUri, ossAuthToken))
    writer.close()
    bom
}

//main function executed in scripting mode 
@main def exec(jarFile: String, 
    projectRootDir: String,
    ossIndexUri : String,
    ossAuthToken : String,  
    outFile: String) : Boolean = {
  
  println("[+] Reset workspace ")
  workspace.reset

  println("[+] Load blacklist ")
  config.frontend.java.cmdLineParams = Seq("-default-blacklist packageblacklist")

  println("[+] Creating CPG and SP for " + jarFile) 
  createCpgAndSp(jarFile)

  println("[+] Verify if CPG was created successfully") 
  if(!workspace.baseCpgExists(jarFile)) {
       println("Failed to create CPG for " + jarFile)
       return false
  }

  println("[+] Check if CPG is loaded")
  if(workspace.loadedCpgs.toList.size == 0) {
       println("Failed to load CPG for " + jarFile)
       return false
  } 

  println("[+] Fetching Dependencies")
  DependencyParser.getDependencies(projectRootDir)

  if(cpg.dependency.l.size == 0) {
       println("Error in fetching dependencies from project Root Directory " + projectRootDir + " for " + jarFile)
       return false
  }

  println("[+] Get CVE and Signatures for dependencies")
  val resultsAsJson = getCVEsForBOM(cpg,
                                ossIndexUri,
                                ossAuthToken)
  
  println("Writing to OutFile : " + outFile)
  val writer = new java.io.PrintWriter(new java.io.File(outFile))
  writer.write(resultsAsJson)
  writer.close()
 
  return true
}