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
 import semmle.code.java.dataflow.DataFlow
 import MyCryptoFlow::PathGraph
 import semmle.code.java.security.Encryption
 import CryptoUtils

 from MyCryptoFlow::PathNode source, MyCryptoFlow::PathNode sink, CryptoAlgoSpecMethod spec, CryptoAlgoLiteral algo
 where 
  source.getNode().asExpr() = algo and
  sink.getNode().asExpr() = spec.getAlgoSpec() and
  MyCryptoFlow::flowPath(source, sink)
select spec, source, sink, "Cryptographic Algorithm is $@ is used.", algo, algo.getValue()
