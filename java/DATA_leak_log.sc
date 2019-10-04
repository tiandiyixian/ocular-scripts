/* DATA_leak_log.sc

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
val title = "[DATA] Sensitive Data (PII/PHI) Leak report"
val description = "Right now, protecting PII/PHI data can be difficult. It’s often spread across and copied to a number of different environments, and it’s hard to know what to restrict it to and where it’s located. This data sprawl inevitably leaves organizations open to data breaches, and not just from hackers either. In its 2017 end of year review of data breaches, the Identity Theft Resource Center revealed that ~10% of breaches were caused by employee error or negligence, ~7% were a result of accidental exposure, and ~5% were down to insider theft. This report uses advanced NLP technology over CPG to identify sensitive data, and thereon plot all pathways of from point of initialization to exit upon outbound channels (FILESYSTEM, NETWORK, LOGGER, etc)."
val recommendation="The purpose of obfuscation is to make something harder to understand, usually for the purposes of making it more difficult to attack or to copy. Apply effective redaction/obfuscation schemes on data flow paths." 

case class Result(title : String, description : String, recommendation : String, flows : List[traces.Flows])

def isPIILeakingToLogs(cpg: io.shiftleft.codepropertygraph.Cpg, nameSpace : String, encryptFunction : Option[String]) = {
    Result(title, 
        description, 
        recommendation,
        data.isPIILeaking(cpg, nameSpace, taint_tags.sinks("LOGGER"), encryptFunction)).asJson.spaces2
}

def createResults(jarFile: String, nameSpace : String, dirPath: String) = {
    val piiLeakFile = dirPath + java.io.File.separator + "DATA_leak_log.json"
    val writer = new java.io.PrintWriter(new java.io.File(piiLeakFile))
    writer.write(isPIILeakingToLogs(cpg, nameSpace, None))
    writer.close()
    piiLeakFile
}

@doc("")
@main def execute(jarFile: String, 
                outFile: String,
                basePkg : String, 
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
            writer.write(isPIILeakingToLogs(cpg, "io.shiftleft", None))
        } else {
            writer.write(isPIILeakingToLogs(cpg, "io.shiftleft", Some(redactFunction)))
        }
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    }
}

