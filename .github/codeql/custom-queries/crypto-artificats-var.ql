/**
 * @name CryptographicArtificatoryVariable
 * @description Variable Matched with Cryptographic Artificatory Keywords  
 * @kind problem
 * @problem.severity	recommendation
 * @id java/type-crypto-variable-match
 * @tags reliability
 *        correctness
 *        logic
 */


import java

// Detect cryptographic-related variables
class CryptoVariable extends LocalVariableDecl {
  CryptoVariable() {
    // Check if the variable name contains cryptographic-related keywords
    this.getName().toLowerCase().matches("%key%") or 
    this.getName().toLowerCase().matches("%crypto%") or 
    this.getName().toLowerCase().matches("%aes%") or 
    this.getName().toLowerCase().matches("%rsa%") or 
    this.getName().toLowerCase().matches("%tls%") or 
    this.getName().toLowerCase().matches("%cipher%") or 
    this.getName().toLowerCase().matches("%hash%") or
    this.getName().toLowerCase().matches("%length%") or
    this.getName().toLowerCase().matches("%size%") or
    this.getName().toLowerCase().matches("%kyber%")
    or
    exists(StringLiteral str | this.getAnAssignedValue() = str and
    (str.getValue().toLowerCase().matches("%key%") or 
     str.getValue().toLowerCase().matches("%crypto%") or 
     str.getValue().toLowerCase().matches("%aes%") or 
     str.getValue().toLowerCase().matches("%rsa%") or 
     str.getValue().toLowerCase().matches("%tls%") or 
     str.getValue().toLowerCase().matches("%cipher%") or 
     str.getValue().toLowerCase().matches("%hash%") or
     str.getValue().toLowerCase().matches("%des%") or
     str.getValue().toLowerCase().matches("%ecdsa%") or
     str.getValue().toLowerCase().matches("%hmac%") or
     str.getValue().toLowerCase().matches("%sha%")) or
     str.getValue().toLowerCase().matches("%kyber%")) 

  }
}
string getVarValue(CryptoVariable v) {
  if exists(Expr arg | arg = v. getInitializer()) 
    then result = v. getInitializer().toString()
    else result = "Garbage value"
}

from CryptoVariable var
select 
  var, 
  "Detected Variable: " + var.getName() +
  " | Value : " +  getVarValue(var) +
  " | Declared At Line: " + var.getLocation().getStartLine().toString() +
  " | Location: " + var.getLocation().getFile().getRelativePath().toString()
