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

String getArgInfo(CryptoMethodCall c) { 
    // Check if the argument is a string literal
    if (exists(StringLiteral arg | arg = c.getArgument(0))) {
        // If it's a string literal, return the value
    then " | Argument: " + c.getArgument(0).toString();
    } else if (exists(VariableAccess var | var = c.getArgument(0))) {
        // If it's a variable, resolve its value
        Variable v = c.getArgument(0).asVariableAccess().getVariable();
        if (v.getInitializer() != null) {
            then " | Argument (Variable Resolved): " + v.getInitializer().toString();
        } else {
            then " | Argument (Variable): Unknown";
        }
    } else {
        // For other cases, return a generic response
        then " | Argument: Complex or Unresolved Expression";
    }
}


from CipherGetInstanceUsage mc 
select mc, "Algorithm " + getArgInfo(mc) +  mc.getLocation().getFile().getRelativePath().toString() +
" Line: " + mc.getLocation().getStartLine().toString()
