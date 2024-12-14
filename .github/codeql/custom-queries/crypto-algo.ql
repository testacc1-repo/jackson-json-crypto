import java
import semmle.code.java.security.Cryptography

from MethodCall call, string algorithm
where
  // Identify cryptographic algorithm usage
  (
    call.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    call.getMethod().getName() = "getInstance" and
    call.getAStringArgument() = algorithm
  ) or
  (
    call.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    call.getMethod().getName() = "getInstance" and
    call.getAStringArgument() = algorithm
  ) or
  (
    call.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") and
    call.getMethod().getName() = "getInstance" and
    call.getAStringArgument() = algorithm
  )
select call, algorithm, call.getLocation()
