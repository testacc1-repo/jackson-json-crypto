/**
 * @name Use of Crypto algo spec
 * @description Using  cryptographic algorithms can allow an attacker to compromise security.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.5
 * @precision medium
 * @id java/potentially-weak-cryptographic-algorithm
 * @tags security
 */

 import java
 import semmle.code.java.security.Encryption
 import semmle.code.java.dataflow.DataFlow
 import semmle.code.java.frameworks.Properties
 import semmle.code.java.security.MaybeBrokenCryptoAlgorithmQuery
 import InsecureCryptoFlow::PathGraph
 
 from InsecureCryptoFlow::PathNode source, InsecureCryptoFlow::PathNode sink, CryptoAlgoSpec c
 where
   sink.getNode().asExpr() = c.getAlgoSpec() and
   InsecureCryptoFlow::flowPath(source, sink)
 select c, source, sink, c.getAlgoSpec().toString()
