import java
import semmle.code.java.security.Encryption
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.security.Sanitizers
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
      m.hasQualifiedName("javax.crypto", "KeyAgreement", "getInstance")
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
