/* DATA_leak_email.sc

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

def isPIILeakingToEmail(cpg: io.shiftleft.codepropertygraph.Cpg, nameSpace : String, redactFunction : Option[String]) = {
    val resultsJson = data.isPIILeakingAsJSON(cpg, nameSpace, taint_tags.sinks("EMAIL"), redactFunction)
    resultsJson
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
            writer.write(isPIILeakingToEmail(cpg, "io.shiftleft", None))
        } else {
            writer.write(isPIILeakingToEmail(cpg, "io.shiftleft", Some(redactFunction)))
        }
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    }
}