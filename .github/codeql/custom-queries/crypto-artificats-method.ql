/**
 * @name CryptographicArtificatoryMethod
 * @description Method Matched with Cryptographic Artificatory Keywords  
 * @kind problem
 * @problem.severity	recommendation
 * @id java/type-crypto-method-match
 * @tags reliability
 *        correctness
 *        logic
 */



import java

class CryptoMethodCall extends MethodCall {
  CryptoMethodCall() {
    // Check if the method matches any cryptographic conditions
    exists(Method m | this.getMethod() = m and (
      // Method name contains cryptographic keywords
      m.getName().toLowerCase().matches("%kyber%") or 
      m.getName().toUpperCase().matches("%TLS%") or
      // Declaring class belongs to cryptographic packages
      m.getDeclaringType().getQualifiedName().toLowerCase().matches("javax.crypto.%") or
      m.getDeclaringType().getQualifiedName().toLowerCase().matches("org.bouncycastle.crypto.%") or
      m.getDeclaringType().getQualifiedName().toLowerCase().matches("java.security.%") or
      m.getDeclaringType().getQualifiedName().toLowerCase().matches("javax.net.ssl.%") or
      m.getDeclaringType().getQualifiedName().toLowerCase().matches("com.google.crypto.tink.%") or
      // Method is "getInstance" and the argument matches known algorithms
      (m.getName() = "getInstance" and 
       exists(StringLiteral l | l = this.getArgument(0) and 
         l.getValue().toUpperCase().matches("%AES%") or
         l.getValue().toUpperCase().matches("%RSA%") or
         l.getValue().toUpperCase().matches("%SHA%") or
         l.getValue().toUpperCase().matches("%Kyber%") or
         l.getValue().toUpperCase().matches("%Dilithium%")) or
      // Argument matches cryptographic protocol patterns
      exists(StringLiteral l | l = this.getArgument(0) and 
        l.getValue().toUpperCase().matches("%TLS%") or
        l.getValue().toUpperCase().matches("%SSL%") or
        l.getValue().toUpperCase().matches("%SSH%"))
    )))
  }
}

string getArgInfo(CryptoMethodCall c) {
  if exists(StringLiteral arg | arg = c.getArgument(0)) 
    then result = " | Argument : " + c.getArgument(0).toString()
    else result = " "
}

from CryptoMethodCall call
select 
  call, 
  "Detected: " + call.getMethod().getDeclaringType().getQualifiedName() +
  " | Method: " + call.getMethod().getName() +
   getArgInfo(call) +
  " | Location: " + call.getLocation().getFile().getRelativePath().toString() +
  " | Line: " + call.getLocation().getStartLine().toString()
