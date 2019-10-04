# Execution Plan

## Baseline Commands (Interactive Mode)

```

//create CPG (Code Property Graph) for appropriate payload
createCpgAndSp("/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war")

//Verify if CPG is created/loaded in workspace (check for isLoaded)
workspace

// Load CPG if not loaded 
loadCpg("servlettarpit.war")

//get all sources 
cpg.source.l.map(_.method.fullName)

//get all sinks
cpg.sink.l.map(_.method.fullName)

//get all literals defined in code
cpg.method.literal.code.l

//get all types (system and user defined types) defined in code
cpg.typeDecl.fullName.l

//get all methods and it's argument list defined in CPG
cpg.method.l.map { m => (m.fullName, m.start.parameter.evalType.l zip m.start.parameter.name.l) }
```

## Attack Surface Extractor (useful in enumeration phase of penetration testing)

### Script Mode 
```
./ocular.sh --script scripts/java/PENTEST_attacksurface.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=attacksurface.json
```

### Interactive Mode
```
import $file.scripts.java.PENTEST_attacksurface

//get attack surface (route, source and associated sinks)
PENTEST_attacksurface.getAttackSurface(cpg)
```


## Data Leak

### Script Mode 
```
./ocular.sh --script scripts/java/DATA_leak_log.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_leak_log.json,basePkg="io.shiftleft",redactFunction="NONE"

./ocular.sh --script scripts/java/DATA_leak_tokens.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_leak_tokens.json,basePkg="io.shiftleft",redactFunction="NONE"

./ocular.sh --script scripts/java/DATA_leak_envvars.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_leak_envvars.json,redactFunction="NONE"

./ocular.sh --script scripts/java/DATA_leak_email.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_leak_email.json,basePkg="io.shiftleft",redactFunction="NONE"
```
### Interactive Mode
```
import $file.scripts.java.utils.data

//Get PII Data qualified by namespace
data.getSensitiveUserDefinedTypes("io.shiftleft")

//Check if PII is leaking to logs
import $file.scripts.java.DATA_leak_log
DATA_leak_log.isPIILeakingToLogs(cpg, "io.shiftleft", None)

//Check if PII is leaking to email
import $file.scripts.java.DATA_leak_email
DATA_leak_email.isPIILeakingToEmail(cpg, "io.shiftleft", None)

//Check if hardcoded credentials exists and if so, are any of them leaking to logs
import $file.scripts.java.DATA_leak_tokens
DATA_leak_tokens.areTokensLeakingToLogs(cpg, None)

//Check if env properties are fetched and if so, are any of them leaking to logs
import $file.scripts.java.DATA_leak_envvars
DATA_leak_envvars.areEnvTokensLeakingToLogs(cpg,None)
```


## CCPA/GDPR Data Mapping exercise

### Script Mode

```
./ocular.sh --script scripts/java/DATA_mapping.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_mapping_redact.json,tracingBeacon="@SensitiveRedact"

./ocular.sh --script scripts/java/DATA_mapping.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=data_mapping_track.json,tracingBeacon="@SensitiveBeacon"
```

### Interactive Mode
```
import $file.scripts.java.DATA_mapping

// Track through code to trace data flows of any data type annotated as @SensitiveRedact
DATA_mapping.getAnnotatedModels(cpg, "@SensitiveRedact")

// Track through code to trace data flows of any data type annotated as @SensitiveBeacon
DATA_mapping.getAnnotatedModels(cpg, "@SensitiveBeacon")
```

## Business Logic Flaws

### Script Mode
```
./ocular.sh --script scripts/java/BIZFLAWS_weak_crypto.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=weak_crypto.json

./ocular.sh --script scripts/java/BIZFLAWS_idor_email.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=idor_email.json,nameSpace="io.shiftleft"
```

### Interactive Mode
```
import $file.scripts.java.BIZFLAWS_weak_crypto.sc

// Track all paths that are initializing and thereafter utlizing a weak crytographic algorithm 
BIZFLAWS_weak_crypto.isWeakAlgorithmUsed(cpg)

import $file.scripts.java.BIZFLAWS_idor_email.sc

// Track all paths in code that directly derefrence a DB resultset and append attributes to a string composed on email transport channel
BIZFLAWS_idor_email.isIDORToEmail(cpg, "io.shiftleft", None)
```

## RootKit and Backdoor detection

### Script Mode
```
./ocular.sh --script scripts/java/ROOTKIT_suspicious_literals.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,outFile=suspicious_literals.json
```

### Interactive Mode
```
import $file.scripts.java.ROOTKITS_suspicious_literals.sc

// Identify all encoded literals (of Base64 encoding type) and thereafter track if it is participating in a flow leading to a dangerous SINK (passing through a BASE64 decode in transit)

ROOTKITS_suspicious_literals.getSuspiciousLiterals(cpg)
```


## SCA - Get CVE Feeds for SCA
```
// Run Ocular in autonomous mode 
./ocular.sh --import scripts/deps.sc --script scripts/sca/bom.sc --params jarFile=/Users/chetanconikee/demoenv/tarpit/target/servlettarpit.war,projectRootDir=/Users/chetanconikee/demoenv/tarpit,ossIndexUri=https://ossindex.sonatype.org/api/v3/component-report,ossAuthToken=Y2hldGFuQHNoaWZ0bGVmdC5pbzoyZjc1YzgyYmIxNGRjYmY1NzRmOTkxYmE3MTEyZjA2NDE5MWFhOWY2,outFile=bomcve.json

//Review results ...
cat bomcve.json | jq 
```