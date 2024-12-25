import java
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.security.Sanitizers
import semmle.code.java.security.Encryption
private import semmle.code.configfiles.ConfigFiles

abstract class CryptoAlgorithm extends Expr {
  abstract string getStringValue();
}

private class ShortStringLiteral extends StringLiteral {
  ShortStringLiteral() { this.getValue().length() < 20 }
}

class CryptoAlgoLiteral extends CryptoAlgorithm, ShortStringLiteral {
  CryptoAlgoLiteral() { this.getValue().length() > 1 }

  override string getStringValue() { result = this.getValue() }
}



class CryptoAlgoSpecMethod extends CryptoAlgoSpec {
  CryptoAlgoSpecMethod() {
    exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("javax.crypto", "Cipher", "getInstance")
    )
    or
    exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("java.security", "MessageDigest", "getInstance")
    )
    or
    exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("javax.net.ssl", "SSLContext", "getInstance")
    )
  }

  override Expr getAlgoSpec() { result = this.(MethodCall).getArgument(0) }
}


module CryptoConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    n.asExpr() instanceof CryptoAlgoLiteral
  }

  predicate isSink(DataFlow::Node n) {
    exists(CryptoAlgoSpecMethod c | n.asExpr() = c.getAlgoSpec())
  }

  additional predicate additionalFlowStep(DataFlow::Node pred, DataFlow::Node succ) {
    // Track flow from field declaration to its use
    exists(FieldAccess fieldAccess, Field f |
      fieldAccess.getField() = f and
      pred.asExpr() = f.getInitializer() and
      succ.asExpr() = fieldAccess
    )
  }
  
 
}

module MyCryptoFlow = DataFlow::Global<CryptoConfig>;




bindingset[algorithmString]
private string algorithmRegex(string algorithmString) {
  result =
    "((^|.*[^A-Z])(" + algorithmString + ")([^A-Z].*|$))" +
      // or...
      "|" +
      // For lowercase, we want to be careful to avoid being confused by camelCase
      // hence we require two preceding uppercase letters to be sure of a case switch,
      // or a preceding non-alphabetic character
      "((^|.*[A-Z]{2}|.*[^a-zA-Z])(" + algorithmString.toLowerCase() + ")([^a-z].*|$))"
}

/**
 * Gets the name of an Algo that is known to be insecure.
 */
string getAnInsecureAlgoName() {
  result =
    [
      "ECIES", "DH", "AES", "DES", "DESede", "Blowfish", "Twofish", "RC4", "RC5", "Serpent", "Camellia", "CAST5", "Skipjack",
      "RSA", "EC", "DH", "ElGamal", "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA256withRSA", "SHA256withDSA", "SHA256withECDSA"
    ]
}

/**
 * Gets the name of a hash Algo that is insecure if it is being used for
 * encryption.
 */
string getAnInsecureHashAlgoName() {
  result = "SHA1" or
  result = "MD5"
}

private string rankedInsecureAlgo(int i) {
  result = rank[i](string s | s = getAnInsecureAlgoName())
}

private string insecureAlgoString(int i) {
  i = 1 and result = rankedInsecureAlgo(i)
  or
  result = rankedInsecureAlgo(i) + "|" + insecureAlgoString(i - 1)
}

/**
 * Gets the regular expression used for matching strings that look like they
 * contain an Algo that is known to be insecure.
 */
string getInsecureAlgoRegex() {
  result = algorithmRegex(insecureAlgoString(max(int i | exists(rankedInsecureAlgo(i)))))
}


class InsecureAlgoLiteral extends CryptoAlgorithm, ShortStringLiteral {
  InsecureAlgoLiteral() {
    exists(string s | s = this.getValue() |
      // Algo identifiers should be at least two characters.
      s.length() > 1 and
      s.regexpMatch(getInsecureAlgoRegex())
    )
  }

  override string getStringValue() { result = this.getValue() }
}

