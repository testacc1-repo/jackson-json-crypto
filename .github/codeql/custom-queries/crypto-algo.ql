/**
 * @name Use of a broken or risky cryptographic algorithm
 * @description Using broken or weak cryptographic algorithms can allow an attacker to compromise security.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id java/weak-cryptographic-algorithm
 * @tags security
 *       external/cwe/cwe-327
 *       external/cwe/cwe-328
 */

 import java
 import semmle.code.java.security.Encryption
 import semmle.code.java.security.BrokenCryptoAlgorithmQuery
 import semmle.code.java.dataflow.DataFlow
 import InsecureCryptoFlow::PathGraph
 import CryptoUtils

  class CryptoAlgoSpecMethod extends CryptoAlgoSpec{
    CryptoAlgoSpecMethod()
    {
      exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("javax.crypto", "Cipher", "getInstance")
      ) or
      exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("javax.crypto", "KeyAgreement", "getInstance")
      ) or
      exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("java.security", "MessageDigest", "getInstance")
      ) or
      exists(Method m | m.getAReference() = this |
      m.hasQualifiedName("javax.net.ssl", "SSLContext", "getInstance")
    )
    }

    override Expr getAlgoSpec() { result = this.(MethodCall).getArgument(0) }
  }
 from CryptoAlgoSpecMethod spec, CryptoAlgoLiteral algo
 where
 DataFlow::localFlow(DataFlow::exprNode(algo), DataFlow::exprNode(spec.getAlgoSpec())) 
select spec, spec.getAlgoSpec() + " " + spec.getLocation().getFile().getRelativePath().toString() +
" Line: " +  spec.getLocation().getStartLine().toString(), algo, algo.getStringValue() + " " + algo.getLocation().getFile().getRelativePath().toString() + " Line: " +  algo.getLocation().getStartLine().toString()
