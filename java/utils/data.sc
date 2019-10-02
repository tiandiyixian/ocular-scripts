/* data.sc
 *
 * Version: 0.0.1
 * Ocular Version: 0.3.34
 * Author: Chetan Conikee <chetan@shiftLeft.io>
 * Execution-mode : Internal
 * Input: Application CPG
 * Output: JSON
 * 
 * Description: 
 * A set of convenience methods to abstarct sensitive data flow analysis
 */

import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`
import $ivy.`io.circe::circe-optics:0.10.0`

// JSON utilities, cursors and decoders 
import io.circe.parser
import io.circe.generic.semiauto.deriveDecoder
import io.circe.generic.auto._
import io.circe.parser._, io.circe.syntax._
import io.circe.Json
import cats.syntax.either._
import io.circe.optics.JsonPath._

import $file.^.utils.taint_tags
import $file.^.utils.traces
import $file.^.utils.token_patterns

def getSensitiveUserDefinedTypes(nameSpace : String) = {
    cpg.sensitiveType.l.map(_.fullName).filter(_.contains(nameSpace))
}

def isPIILeaking(cpg: io.shiftleft.codepropertygraph.Cpg,
                 nameSpace : String, 
                 to : String,
                 encryptFunction : Option[String]) = {

    val sensitiveTypes = getSensitiveUserDefinedTypes(nameSpace)
    sensitiveTypes map { s =>
        val sExpr = ".*" + s + ".*"
        val source = cpg.local.evalType(sExpr).referencingIdentifiers
        val sink = cpg.method.fullName(to).parameter
        encryptFunction match {
            case Some(e) => traces.printFlows(sink.reachableBy(source).flows.passesNot(e))
            case None => traces.printFlows(sink.reachableBy(source).flows)
        }
    }
}

def isPIILeakingAsJSON(cpg: io.shiftleft.codepropertygraph.Cpg,
                 nameSpace : String, 
                 to : String,
                 encryptFunction : Option[String]) = {

    val sensitiveTypes = getSensitiveUserDefinedTypes(nameSpace)
    val results = sensitiveTypes map { s =>
        val sExpr = ".*" + s + ".*"
        val source = cpg.local.evalType(sExpr).referencingIdentifiers
        val sink = cpg.method.fullName(to).parameter
        encryptFunction match {
            case Some(e) => traces.getFlowTrace(sink.reachableBy(source).flows.passesNot(e))
            case None => traces.getFlowTrace(sink.reachableBy(source).flows)
        }
    } 
    results.filter(!_.isEmpty).asJson.spaces2
}


def areTokensLeaking(cpg: io.shiftleft.codepropertygraph.Cpg, to : String, encryptFunction : Option[String]) = {
    
    val literals = cpg.literal.code.l.distinct.map(_.replaceAll("^\"|\"$", "")).
                        filterNot(i => java.util.regex.Pattern.matches("[0-9]{1,3}",i) || 
                                i.equals("null") || 
                                i.equals(""))

    val matchList = literals.map { literal =>
                token_patterns.sensitiveTokenPatterns map { tokenPattern =>
                     (java.util.regex.Pattern.matches(tokenPattern.expr,literal), tokenPattern, literal)
        }
    }.flatten filter(r => r._1.equals(true))

    val results = matchList map { m => 
        val sExpr = ".*" + m._3 + ".*"
        val source = cpg.literal.code(sExpr)
        val sink = cpg.method.fullName(to).parameter
        encryptFunction match {
            case Some(e) => traces.getFlowTrace(sink.reachableBy(source).flows.passesNot(e))
            case None => traces.getFlowTrace(sink.reachableBy(source).flows)
        }
    }
    results.filter(!_.isEmpty).asJson.spaces2
}

def areEnvTokensLeaking(cpg: io.shiftleft.codepropertygraph.Cpg, to : String, encryptFunction : Option[String]) = {
    val source = cpg.method.fullName(taint_tags.sources("SYSTEM")).parameter
    val sink = cpg.method.fullName(to).parameter
    encryptFunction match {
        case Some(e) => traces.getFlowTraceAsJson(sink.reachableBy(source).flows.passesNot(e))
        case None => traces.getFlowTraceAsJson(sink.reachableBy(source).flows)
    }
}