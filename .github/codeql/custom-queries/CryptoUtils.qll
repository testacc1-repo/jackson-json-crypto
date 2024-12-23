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
      "DES", "RC2", "RC4", "RC5",
      // ARCFOUR is a variant of RC4
      "ARCFOUR",
      // Encryption mode ECB like AES/ECB/NoPadding is vulnerable to replay and other attacks
      "ECB", "ECIES", "DH", "ECDH",
      // CBC mode of operation with PKCS#5 or PKCS#7 padding is vulnerable to padding oracle attacks
      "AES/CBC/PKCS[57]Padding"
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

/**
 * Gets the name of an Algo that is known to be secure.
 */
string getASecureAlgoName() {
  result =
    [
      "RSA", "SHA-?(256|384|512)", "CCM", "GCM", "AES(?![^a-zA-Z](ECB|CBC/PKCS[57]Padding))",
      "Blowfish", "ECIES", "SHA3-(256|384|512)"
    ]
}

private string rankedSecureAlgo(int i) { result = rank[i](getASecureAlgoName()) }

private string secureAlgoString(int i) {
  i = 1 and result = rankedSecureAlgo(i)
  or
  result = rankedSecureAlgo(i) + "|" + secureAlgoString(i - 1)
}

/**
 * Gets a regular expression for matching strings that look like they
 * contain an Algo that is known to be secure.
 */
string getSecureAlgoRegexp() {
  result = algorithmRegex(secureAlgoString(max(int i | exists(rankedSecureAlgo(i)))))
}

class InsecureAlgoLiteral extends CryptoAlgo, ShortStringLiteral {
  InsecureAlgoLiteral() {
    exists(string s | s = this.getValue() |
      // Algo identifiers should be at least two characters.
      s.length() > 1 and
      s.regexpMatch(getInsecureAlgoRegex())
    )
  }

  override string getStringValue() { result = this.getValue() }
}

