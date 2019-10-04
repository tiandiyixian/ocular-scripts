/* ROOTKITS_suspicious_literals

   Version: 0.0.1
   Ocular Version: 0.3.70
   Author: Chetan Conikee <chetan@shiftLeft.io>
   Input: Application JAR/WAR/EAR
   Output: JSON

 */

import $ivy.`com.github.javaparser:javaparser-core:2.0.0`
import $ivy.`me.xdrop:fuzzywuzzy:1.2.0`

import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`
import $ivy.`io.circe::circe-optics:0.10.0`

import me.xdrop.fuzzywuzzy.FuzzySearch

import com.github.javaparser.Providers.provider
import com.github.javaparser.JavaParser
import com.github.javaparser.ParseStart._

import $file.^.java.utils.taint_tags
import $file.^.java.utils.traces
import $file.^.java.utils.token_patterns
import $file.^.java.utils.data

// JSON utilities, cursors and decoders 
import io.circe.parser
import io.circe._, io.circe.generic.semiauto._
import io.circe.generic.auto._
import io.circe.parser._, io.circe.syntax._
import io.circe.Json
import cats.syntax.either._
import io.circe.optics.JsonPath._

import scala.collection.mutable.ListBuffer

// Report title and description
val title = "[ROOTKIT] Detect Suspicious Literals and it's associated flows"
val description = "A rootkit is a clandestine computer program designed to provide continued privileged access to a computer while actively hiding its presence. Malicious developers are the ultimate insiders. With a very small number of lines of Java, they can steal all your data, corrupt systems, install system level attacks, and cover their tracks. A trojaned Struts or Log4j library could affect most of the financial industry at once."
val recommendation="Identify hard-coded encoded patterns in source code and thereafter track the information flow path to assess what is being done with it. Use the report to tack whether these encoded patterns are touching a sensitive sink (as a consquence of being triggered at a scheduled interval [or] request workflow)." 

object CodeType extends Enumeration {
    type CodeType = Value
    val javaCode = Value("JAVA_CODE")
    val shellScript = Value("SHELL_SCRIPT")
    val dangerousCommand = Value("DANGEROUS_COMMAND")
    val notdetected = Value("NOTDETECTED")
}

import CodeType.CodeType

case class Encoding(encoded : String, decoded : String, codeType : CodeType)
case class Tag(name : String, tagRegex : String, encoded : Option[Encoding])

case class RootKit(encoded : String, decoded : String, codeType : String, flows : List[traces.Flows])

case class Result(title : String, description : String, recommendation : String, rootKits : List[RootKit])

case class Literals(matchedVal : String, 
    tags : List[Tag],
    flowTraces : Option[List[String]])

def isShellCode(decodedLiteral : String) : Boolean = {
    decodedLiteral.contains(".exe") || 
    decodedLiteral.contains(".sh")
}

def isSuspiciousCommand(command : String) = {
    token_patterns.badCommandPatterns.
        filter(cmd => FuzzySearch.partialRatio(command, cmd.pattern) >= 70).
        map(_.toString)
}

def getSuspiciousLiterals(cpg: io.shiftleft.codepropertygraph.Cpg) = {

    var rootKits = new ListBuffer[RootKit]()

    val javaParser = new JavaParser()
    val base64EncodingPattern = token_patterns.base64Pattern

    val literals = cpg.literal.code.l.distinct.map(_.replaceAll("^\"|\"$", "")).
                        filterNot(i => java.util.regex.Pattern.matches("[0-9]{1,3}",i) || 
                                        i.equals("null") || 
                                        i.equals(""))

    val matches = literals.filter(java.util.regex.Pattern.matches(base64EncodingPattern,_))

    val suspiciousLiterals = matches.map { m =>
            val decodedValue = new String(java.util.Base64.getDecoder.decode(m))
            val isJavaCode = javaParser.parse(COMPILATION_UNIT, provider(decodedValue))
            val dangerousCommand = isSuspiciousCommand(decodedValue)
            if(isJavaCode.isSuccessful) {
                Encoding(m, decodedValue, CodeType.javaCode)
            } else {
                val isShellScript = isShellCode(decodedValue)
                if(isShellScript) {
                    Encoding(m, decodedValue, CodeType.shellScript)
                } else {
                    if(!dangerousCommand.isEmpty) {
                        Encoding(m, decodedValue, CodeType.dangerousCommand)
                    } else {
                        Encoding(m, decodedValue, CodeType.notdetected)
                    }
                }
            } 
    } filter(!_.codeType.equals(CodeType.notdetected)) groupBy(_.codeType)

    suspiciousLiterals foreach { case(codeType,encodings) => 
        codeType match {
            case CodeType.javaCode => 
                encodings foreach { e => 
                    val literalExpr = ".*" + e.encoded + ".*"
                    val source = cpg.literal.code(literalExpr)
                    val sink = cpg.method.fullName(taint_tags.sinks("FILE")).parameter
                    val f = traces.getFlowTrace(sink.reachableBy(source).flows.passes(taint_tags.sinks("DECODE")))
                    rootKits += RootKit(e.encoded,e.decoded,"JAVA_CODE",f)
                }
            case CodeType.shellScript => 
                encodings foreach { e => 
                    val literalExpr = ".*" + e.encoded + ".*"
                    val source = cpg.literal.code(literalExpr)
                    val sink = cpg.method.fullName(taint_tags.sinks("COMMAND_INJECTION")).parameter
                    val f = traces.getFlowTrace(sink.reachableBy(source).flows.passes(taint_tags.sinks("DECODE")))
                    rootKits += RootKit(e.encoded,e.decoded,"SHELL_SCRIPT",f)
                }
            case CodeType.dangerousCommand =>
                 encodings foreach { e => 
                    val literalExpr = ".*" + e.encoded + ".*"
                    val source = cpg.literal.code(literalExpr)
                    val sink = cpg.method.fullName(taint_tags.sinks("COMMAND_INJECTION")).parameter
                    val f = traces.getFlowTrace(sink.reachableBy(source).flows.passes(taint_tags.sinks("DECODE")))
                    rootKits += RootKit(e.encoded,e.decoded,"DANGEROUS_COMMAND",f)
                }     
        }
    } 
    Result(title, 
        description,
        recommendation, 
        rootKits.toList).asJson.spaces2
}

def createResults(jarFile: String, dirPath: String) = {
    val rootKitFile = dirPath + java.io.File.separator + "ROOTKITS_suspicious_literals.json"
    val writer = new java.io.PrintWriter(new java.io.File(rootKitFile))
    writer.write(getSuspiciousLiterals(cpg))
    writer.close()
    rootKitFile
}

@doc("")
@main def execute(jarFile: String, outFile: String) : Boolean = {
    
    println("[+] Verify if CPG exists") 
    if(workspace.baseCpgExists(jarFile)) {

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

        } else {

            println("Writing to OutFile : " + outFile)
            val writer = new java.io.PrintWriter(new java.io.File(outFile))
            writer.write(getSuspiciousLiterals(cpg))
            writer.close()
            
            printf("[+] Saving results to %s\n", outFile)
            
            return true
        }
    } else {
        return false
    }
}
