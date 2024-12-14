import java

from MethodCall call, string algorithm
where
  // Identify cryptographic algorithm usage
  (
    call.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", "Cipher") and
    call.getMethod().getName() = "getInstance" and
    call.getArgument(0).toString() = algorithm
  ) or
  (
    call.getMethod().getDeclaringType().hasQualifiedName("java.security", "MessageDigest") and
    call.getMethod().getName() = "getInstance" and
    call.getArgument(0).toString() = algorithm
  ) or
  (
    call.getMethod().getDeclaringType().hasQualifiedName("java.security", "Signature") and
    call.getMethod().getName() = "getInstance" and
    call.getArgument(0).toString() = algorithm
  )
select call, algorithm, call.getLocation()
