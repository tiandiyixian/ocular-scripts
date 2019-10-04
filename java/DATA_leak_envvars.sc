/* DATA_leak_envvars.sc

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

import $file.^.java.utils.taint_tags
import $file.^.java.utils.traces
import $file.^.java.utils.token_patterns
import $file.^.java.utils.data

// JSON utilities, cursors and decoders 
import io.circe.parser
import io.circe.generic.semiauto.deriveDecoder
import io.circe.generic.auto._
import io.circe.parser._, io.circe.syntax._
import io.circe.Json
import cats.syntax.either._
import io.circe.optics.JsonPath._

// Report title and description
val title = "[DATA] Sensitive Environment variables leaking to Log File"
val description = "Every application that connects to the Internet utilizes a data, key (or secret) for identification of their customers and authorization to third-party services. These keys typically identify the app or project that’s making a call to the Application Programming Interface (API) and authorize it for access. Typically, an API key gives full access to every operation an API can perform, including writing new data or deleting existing data. In order to to assess and mitigate the risks associated with information leaks, it’s important to have a deep understanding of how your secrets may be exposed. Even if the repository is private, it should never be used to store sensitive keys and secrets. This report analyzes CPG to discover references to environment variables and thereafter conducts data-flow analysis to identify if such variables are leaked on the log channel without adequate encryption, redaction or obfuscation"
val recommendation="The purpose of obfuscation is to make something harder to understand, usually for the purposes of making it more difficult to attack or to copy. Apply effective redaction/obfuscation schemes on data flow paths." 

case class Result(title : String, description : String, recommendation : String, flows : List[traces.Flows])

def areEnvVarsLeakingToLogs(cpg: io.shiftleft.codepropertygraph.Cpg, encryptFunction : Option[String]) = {
    Result(title, 
        description, 
        recommendation,
        data.areEnvTokensLeaking(cpg,taint_tags.sinks("LOGGER"), encryptFunction)).asJson.spaces2
}

def createResults(jarFile: String, dirPath: String) = {
    val envLeakFile = dirPath + java.io.File.separator + "DATA_leak_envvars.json"
    val writer = new java.io.PrintWriter(new java.io.File(envLeakFile))
    writer.write(areEnvVarsLeakingToLogs(cpg, None))
    writer.close()
    envLeakFile
}

@doc("")
@main def execute(jarFile: String, 
                outFile: String,
                redactFunction : String) : Boolean = {
    
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
        if(redactFunction == "NONE") {
            writer.write(areEnvVarsLeakingToLogs(cpg, None))
        } else {
            writer.write(areEnvVarsLeakingToLogs(cpg, Some(redactFunction)))
        }
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    }
}