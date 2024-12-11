/**
 * @name CryptographicArtificatoryVariable
 * @description Variable Matched with Cryptographic Artificatory Keywords
 * @kind problem
 * @problem.severity recommendation
 * @id java/type-crypto-variable-match
 * @tags reliability
 *        correctness
 *        logic
 */

import java

// Detect cryptographic-related variables and nodes
class CryptoVariable extends AnyNode {
  CryptoVariable() {
    // Check if the node represents a variable name or value containing cryptographic-related keywords
    this.getName().toLowerCase().matches("%key%") or
    this.getName().toLowerCase().matches("%aes%") or
    this.getName().toLowerCase().matches("%rsa%") or
    this.getName().toLowerCase().matches("%tls%") or
    this.getName().toLowerCase().matches("%hash%") or
    this.getName().toLowerCase().matches("%length%") or
    this.getName().toLowerCase().matches("%size%") or
    this.getName().toLowerCase().matches("%kyber%") or
    exists(StringLiteral str | 
      str.getValue().toLowerCase().matches("%key%") or 
      str.getValue().toLowerCase().matches("%aes%") or 
      str.getValue().toLowerCase().matches("%rsa%") or 
      str.getValue().toLowerCase().matches("%tls%") or 
      str.getValue().toLowerCase().matches("%hash%") or
      str.getValue().toLowerCase().matches("%length%") or
      str.getValue().toLowerCase().matches("%size%") or
      str.getValue().toLowerCase().matches("%kyber%") or
      str.getValue().toLowerCase().matches("%des%") or
      str.getValue().toLowerCase().matches("%ecdsa%") or
      str.getValue().toLowerCase().matches("%hmac%") or
      str.getValue().toLowerCase().matches("%sha%")) or
    exists(VariableAccess va | 
      va.getTarget().isFinal() and
      (va.getTarget().getName().toLowerCase().matches("%key%") or 
       va.getTarget().getName().toLowerCase().matches("%aes%") or 
       va.getTarget().getName().toLowerCase().matches("%rsa%") or 
       va.getTarget().getName().toLowerCase().matches("%tls%") or 
       va.getTarget().getName().toLowerCase().matches("%hash%") or
       va.getTarget().getName().toLowerCase().matches("%length%") or
       va.getTarget().getName().toLowerCase().matches("%size%") or
       va.getTarget().getName().toLowerCase().matches("%kyber%"))) or
    exists(NewClassExpr obj | 
      obj.getType().getName().toLowerCase().matches("%cipher%") or 
      obj.getType().getName().toLowerCase().matches("%keygenerator%") or 
      obj.getType().getName().toLowerCase().matches("%secure%") or 
      obj.getType().getName().toLowerCase().matches("%ivparameterspec%") or 
      obj.getType().getName().toLowerCase().matches("%secretkey%")) or
    exists(TypeAccess type | 
      type.getName().toLowerCase().matches("%aes%") or 
      type.getName().toLowerCase().matches("%rsa%") or 
      type.getName().toLowerCase().matches("%tls%") or 
      type.getName().toLowerCase().matches("%ecdsa%") or 
      type.getName().toLowerCase().matches("%sha%") or 
      type.getName().toLowerCase().matches("%hmac%") or 
      type.getName().toLowerCase().matches("%pbkdf%") or 
      type.getName().toLowerCase().matches("%kyber%") or 
      type.getName().toLowerCase().matches("%hash%"))
  }
}

string getVarValue(CryptoVariable v) {
  if exists(Expr arg | arg = v.getInitializer()) 
    then result = v.getInitializer().toString()
    else result = "Garbage value"
}

from CryptoVariable var
select 
  var, 
  "Detected Variable: " + var.getName() +
  " | Value : " + getVarValue(var) +
  " | Declared At Line: " + var.getLocation().getStartLine().toString() +
  " | Location: " + var.getLocation().getFile().getRelativePath().toString()
