/**
 * @name CryptographicArtificatoryUsage
 * @description Method Matched with Cryptographic Artificatory Usage  
 * @kind problem
 * @problem.severity	recommendation
 * @id java/type-crypto-method-match
 * @tags reliability
 *        correctness
 *        logic
 */



 import java
 import semmle.code.java.dataflow.DataFlow
 
 class CryptoMethodInstanceUsage extends MethodCall {
     CryptoMethodInstanceUsage() {
       exists(Method m | this.getMethod() = m and ((
       m.getDeclaringType().getQualifiedName().matches("javax.crypto%") or
       m.getDeclaringType().getQualifiedName().matches("java.security%") or
       m.getDeclaringType().getQualifiedName().matches("javax.net%") )and
       m.getName() = "getInstance")
       )
     }
 }      
 
 
 from CryptoMethodInstanceUsage mc, Parameter p
 where  DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(call.getArgument(0)))

 select mc, "Algorithm " + p + " " +  mc.getLocation().getFile().getRelativePath().toString() +
 " Line: " +  mc.getLocation().getStartLine().toString()
