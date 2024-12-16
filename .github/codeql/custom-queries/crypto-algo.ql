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

class CipherGetInstanceUsage extends MethodCall {
    CipherGetInstanceUsage() {
      exists(Method m | this.getMethod() = m and (
      (m.getDeclaringType().getQualifiedName().matches("javax.crypto%") or
      m.getDeclaringType().getQualifiedName().matches("java.security%") or
      m.getDeclaringType().getQualifiedName().matches("javax.net%") )and
      m.getName() = "getInstance"
      ))
    }
}      

from CipherGetInstanceUsage mc 
select mc, "Algorithm " + mc.getArgument(0).toString() +  mc.getLocation().getFile().getRelativePath().toString() +
" Line: " + mc.getLocation().getStartLine().toString()
