/* BIZFLAWS_idor_email

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
val title = "[DATA] Detect for (IDOR) Insecure Direct Object Reference"
val description = "Insecure Direct Object Reference (called IDOR from here) occurs when a application exposes a reference to an internal implementation object. Using this way, it reveals the real identifier and format/pattern used of the element in the storage backend side. The most common example of it (altrough is not limited to this one) is a record identifier in a storage system (database, filesystem and so on). There can be many variables in the application such as “id”, “pid”, “uid”. Although these values are often seen as HTTP parameters, they can also be found in hyperlinks embedded in emails, HTTP headers and cookies. The attacker can access, edit or delete any of other users’ objects by changing the values. This vulnerability is called IDOR."
val recommendation="The proposal use a hash to replace the direct identifier. This hash is salted with a value defined at application level in order support topology in which the application is deployed in multi-instances mode (case for production). Reference : https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md#proposition"

case class Result(title : String, description : String, recommendation : String, flows : List[traces.Flows])

def isPIILeakingToEmail(cpg: io.shiftleft.codepropertygraph.Cpg, nameSpace : String, redactFunction : Option[String]) = {
    Result(title, 
        description, 
        recommendation,
        data.isPIILeaking(cpg, nameSpace, taint_tags.sinks("EMAIL"), redactFunction)).asJson.spaces2
}

def isIDORToEmail(cpg: io.shiftleft.codepropertygraph.Cpg, nameSpace : String, randomFunction : Option[String]) = {
    isPIILeakingToEmail(cpg, nameSpace, randomFunction)
}

def createResults(jarFile: String, nameSpace : String, dirPath: String) = {
    val idorFile = dirPath + java.io.File.separator + "BIZFLAWS_idor_email.json"
    val writer = new java.io.PrintWriter(new java.io.File(idorFile))
    writer.write(isIDORToEmail(cpg, nameSpace, None))
    writer.close()
    idorFile
}

@doc("")
@main def execute(jarFile: String, nameSpace : String, outFile: String) : Boolean = {
    
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
        writer.write(isIDORToEmail(cpg, nameSpace, None))
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    }
}