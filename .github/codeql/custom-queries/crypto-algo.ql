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
      m.getDeclaringType().hasQualifiedName("javax.crypto%") or
      m.getDeclaringType().hasQualifiedName("java.security%") or
      m.getDeclaringType().hasQualifiedName("javax.net%") and
      m.getName() = "getInstance"
      ))
    }
}      

from CipherGetInstanceUsage mc 
select mc, mc.getArgument(0), mc.getLocation()
