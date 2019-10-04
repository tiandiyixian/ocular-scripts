import $ivy.`com.lihaoyi::requests:0.1.7`
import $ivy.`com.47deg::github4s:0.20.1`
import $ivy.`org.json4s::json4s-jackson:3.6.5`
import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`

import org.json4s._
import org.json4s.jackson.JsonMethods._
import org.json4s.JsonDSL._
import org.json4s.jackson.Serialization._
import org.json4s.native.Serialization.writePretty

import java.nio.charset.StandardCharsets._
import java.nio.file.{Files, Paths}
import io.shiftleft.passes.{CpgPass, DiffGraph}
import io.shiftleft.codepropertygraph.Cpg

import java.io.File
import scala.sys.process._

case class JsonDependency(group: String, name: String, version: String)

object DependencyParser {
 
  def getDependencies(shellScriptDir : String, directory: String): Unit = {
    val shellScript = shellScriptDir + java.io.FileSeperator + "deps.sh"
    readDependencies(StringInput(Process(shellScript, new File(directory)).!!))
  }

  def readDependencies(filename: String): Unit = {
    readDependencies(FileInput(new File(filename)))
  }

  def readDependencies(source: JsonInput): Unit = {
    implicit val jsonFormats = DefaultFormats

    class DependencyPass(cpg : Cpg) extends CpgPass(cpg) {
      override def run(): Iterator[DiffGraph] = {
        val result = new DiffGraph
        (parse(source) \ "dependencies").extract[List[JsonDependency]].foreach { d =>
          result.addNode(new nodes.NewDependency(d.version, d.name, Some(d.group)))
        }
        Iterator(result)
      }
    }
    new DependencyPass(cpg).createAndApply()
  }
}
