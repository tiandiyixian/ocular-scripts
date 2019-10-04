/* traces.sc
 *
 * Version: 0.0.1
 * Ocular Version: 0.3.34
 * Author: Chetan Conikee <chetan@shiftLeft.io>
 * Execution-mode : Internal
 * Input: Application CPG
 * Output: JSON
 * 
 * Description: 
 * The following script is intended to be used for pretty printing
 * of data flows (as JSON, STDOUT) 
 */

import $ivy.`io.circe::circe-core:0.10.0`
import $ivy.`io.circe::circe-generic:0.10.0`
import $ivy.`io.circe::circe-parser:0.10.0`

import io.circe.Json
import io.circe.syntax._
import io.circe.generic.auto._


case class FlowTrace(methodName :String, parameter :String,fileName :String, linNumber :String)
case class Flows(source : String, sink : String, flowTrace : List[FlowTrace])

def locations(flow: nodes.NewFlow): List[nodes.NewLocation] =
     flow.points.map(_.elem.location.asInstanceOf[nodes.NewLocation])

def getFlowTrace(flows: io.shiftleft.dataflowengine.language.NewFlow) = {
  
  val flowList = flows.l
  val newLocations = flowList.map { f => 
    (f.source.method.fullName,
     f.sink.method.fullName,
     f.points.map(_.elem.location.asInstanceOf[nodes.NewLocation]))
  }
  val allFlows = newLocations map { flowList =>
    val flowTraceList = flowList._3.map { flow =>
      val line = flow.lineNumber.getOrElse("SYSTEM")
      FlowTrace(flow.methodShortName,flow.symbol,flow.filename,line.toString)
    }
    Flows(flowList._1,
          flowList._2,
          flowTraceList)
  }
  allFlows
}

def getFlowTraceAsJson(flows: io.shiftleft.dataflowengine.language.NewFlow) = {
  val flowList = flows.l
  val newLocations = flowList.map { f => 
    (f.source.method.fullName,
     f.sink.method.fullName,
     f.points.map(_.elem.location.asInstanceOf[nodes.NewLocation]))
  }
  val allFlows = newLocations map { flowList =>
    val flowTraceList = flowList._3.map { flow =>
      val line = flow.lineNumber.getOrElse("SYSTEM")
      FlowTrace(flow.methodShortName,flow.symbol,flow.filename,line.toString)
    }
    Flows(flowList._1,
          flowList._2,
          flowTraceList)
  }
  allFlows.asJson.spaces2
}


// This convenience method take CPG flows and referencing identifiers (literals) 
// as input and returns a formatted JSON as output
def getFlowTraceAsJson(dataType : String, flows: io.shiftleft.dataflowengine.language.NewFlow): String = {
  val flow = flows.head
  val locs: List[nodes.NewLocation] = locations(flow)
  val f = locs.map { location =>
    val line = location.lineNumber.getOrElse("SYSTEM")
    FlowTrace(location.methodShortName,location.symbol,location.filename,line.toString)
  }
  val results = dataType -> f
  results.asJson.spaces2
}

// This convenience method take CPG flows and referencing identifiers (literals) 
// as input and returns a formatted JSON as output
def getFlowTrace(dataType : String, flows: io.shiftleft.dataflowengine.language.NewFlow) = {
  val flow = flows.head
  val locs: List[nodes.NewLocation] = locations(flow)
  val f = locs.map { location =>
    val line = location.lineNumber.getOrElse("SYSTEM")
    FlowTrace(location.methodShortName,location.symbol,location.filename,line.toString)
  }
  val results = dataType -> f
  results
}

// This convenience method take CPG flows as input and returns a formatted output to STDOUT
def printFlows(flows : io.shiftleft.dataflowengine.language.NewFlow) = {
  import io.shiftleft.dataflowengine.language.{Flow, FlowPrettyPrinterExt}
  val flowList = flows.l
  if(flowList.size > 0) {
    Some(FlowPrettyPrinterExt.prettyPrint(flowList.head))
  } else {
    None
  }
}


