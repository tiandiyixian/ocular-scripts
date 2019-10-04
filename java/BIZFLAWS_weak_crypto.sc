/* BIZFLAWS_weak_crypto

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
val title = "[DATA] Detect for insecure or weak cryptographic algorithms"
val description = "Encryption is the process of using mathematical algorithms to obscure the meaning of a piece of information so that only authorized parties can decipher it. It is used to protect our data (including texts, conversations ad voice), be it sitting on a computer or it being transmitted over the Internet. Encryption technologies are one of the essential elements of any secure computing environment. Java suppors many secure encryption algorithms but some of them are weak to be used in security-intensive applications. For example, the Data Encryption Standard (DES) encryption algorithm is considered highly insecure; messages encrypted using DES have been decrypted by brute force within a single day. This report verifies if the following conditions in source code : Choosing the correct algorithm, Choosing the right mode of operation, hoosing the right padding scheme, hoosing the right keys and their sizes"
val recommendation="Storing credentials in plaintext must never be an option. Hashing alone is not sufficient to mitigate more involved attacks such as rainbow tables. A better way to store credentials is to add a salt to the hashing process: adding additional random data to the input of a hashing function that makes each credentials hash unique. There are plenty of cryptographic functions to choose from such as the SHA2 family and the SHA-3 family. However, one design problem with the SHA families is that they were designed to be computationally fast. Faster calculations mean faster brute-force attacks, for example. Modern hardware in the form of CPUs and GPUs could compute millions, or even billions, of SHA-256 hashes per second. Use  industry-grade and battle-tested bcrypt algorithm to securely hash and salt passwords."

case class Result(title : String, description : String, recommendation : String, flows : List[traces.Flows])

def isWeakAlgorithmUsed(cpg: io.shiftleft.codepropertygraph.Cpg) = {
    val source = cpg.method.literal.code(token_patterns.weakCrypto)
    val sink = cpg.method.fullName(".*doFinal.*|.*javax.crypto.Cipher.init.*").parameter
     Result(title, 
        description, 
        recommendation,
        traces.getFlowTrace(sink.reachableBy(source).flows)).asJson.spaces2
}

def createResults(jarFile: String, dirPath: String) = {
    val weakCryptoFile = dirPath + java.io.File.separator + "BIZFLAWS_weak_crypto.json"
    val writer = new java.io.PrintWriter(new java.io.File(weakCryptoFile))
    writer.write(isWeakAlgorithmUsed(cpg))
    writer.close()
    weakCryptoFile
}

@doc("")
@main def execute(jarFile: String, outFile: String) : Boolean = {

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
        writer.write(isWeakAlgorithmUsed(cpg))
        writer.close()
        
        printf("[+] Saving results to %s\n", outFile)
        
        return true
    }
}