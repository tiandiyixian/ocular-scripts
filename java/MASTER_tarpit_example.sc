import $file.^.java.utils.taint_tags
import $file.^.java.utils.traces
import $file.^.java.utils.token_patterns
import $file.^.java.utils.data

import $file.^.java.BIZFLAWS_idor_email
import $file.^.java.BIZFLAWS_weak_crypto
import $file.^.java.DATA_leak_email
import $file.^.java.DATA_leak_envvars
import $file.^.java.DATA_leak_log
import $file.^.java.DATA_leak_tokens
import $file.^.java.DATA_mapping
import $file.^.java.PENTEST_attacksurface
import $file.^.java.ROOTKIT_suspicious_literals
import $file.^.java.SCA_bom

@doc("")
@main def execute(jarFile: String, 
                outFolder: String) : Boolean = {
    
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
        
        println("Analyzing for Rootkits ...")
        val rootkitResults = ROOTKIT_suspicious_literals.createResults(jarFile,outFolder)
        printf("[+] Saving results to %s\n", rootkitResults)
        
        println("Analyzing for Business Logic Flaw - Insecure Direct Object Reference ...")
        val idorResults = BIZFLAWS_idor_email.createResults(jarFile,"io.shiftleft",outFolder)
        printf("[+] Saving results to %s\n", idorResults)

        println("Analyzing for Business Logic Flaw - Weak Crypto ...")
        val weakCryptoResults = BIZFLAWS_weak_crypto.createResults(jarFile,outFolder)
        printf("[+] Saving results to %s\n", weakCryptoResults)

        println("Analyzing Data Mapping for Complaince (CCPA, GDPR, SOC-*) violations ...")
        val datamapResults = DATA_mapping.createResults(jarFile,outFolder,"@SensitiveRedact")
        printf("[+] Saving results to %s\n", datamapResults)

        println("Analyzing sensitive hard coded tokens leaking on LOGGER channel ...")
        val hcResults = DATA_leak_tokens.createResults(jarFile,outFolder)
        printf("[+] Saving results to %s\n", hcResults)

        println("Analyzing system/environment data is leaking on LOGGER channel ...")
        val enVarResults = DATA_leak_envvars.createResults(jarFile,outFolder)
        printf("[+] Saving results to %s\n", enVarResults)

        println("Analyzing sensitive user defined data is leaking on LOGGER channel ...")
        val udResults = DATA_leak_log.createResults(jarFile, "io.shiftleft", outFolder)
        printf("[+] Saving results to %s\n", udResults)

        println("Analyzing sensitive user defined data is leaking on EMAIL channel ...")
        val leakEmailResults = DATA_leak_email.createResults(jarFile, "io.shiftleft", outFolder)
        printf("[+] Saving results to %s\n", leakEmailResults)

        println("Extracting Attack Surface for RED teaming ...")
        val asResults = PENTEST_attacksurface.createResults(jarFile,outFolder)
        printf("[+] Saving results to %s\n", asResults)

        workspace.reset 

        return true
    }
}