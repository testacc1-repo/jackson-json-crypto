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


string getArgInfo(CryptoMethodInstanceUsage c) { 
    // Check if the argument is a string literal
    if (exists(StringLiteral arg | arg = c.getArgument(0)))
    then result = "Argument: " + c.getArgument(0).toString()
    else if (exists(VarAccess var | var = c.getArgument(0)))
    then result = "Argument " + c.getArgument(0).getAnAssignedValue().toString()
    else result = "Argument: Complex or Unresolved Expression"
    
}


from CryptoMethodInstanceUsage mc 
select mc, "Algorithm " + getArgInfo(mc) + " " +  mc.getLocation().getFile().getRelativePath().toString() +
" Line: " +  mc.getLocation().getStartLine().toString()
