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
      this.getTarget().getDeclaringType().hasQualifiedName("javax.crypto%") or
      this.getTarget().getDeclaringType().hasQualifiedName("java.security%") or
      this.getTarget().getDeclaringType().hasQualifiedName("javax.net%") and
      this.getTarget().getName() = "getInstance"
    }
}      

from CipherGetInstanceUsage mc 
select mc, mc.getArgument(0), mc.getLocation()
