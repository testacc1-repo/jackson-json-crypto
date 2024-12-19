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
 import semmle.code.java.security.Encryption
 import MyCryptoFlow::PathGraph
 import CryptoUtils
 import MyCryptoFlow

 from DataFlow::Node source, DataFlow::Node sink, CryptoAlgoSpecMethod spec, CryptoAlgoLiteral algo
 where 
  sink.asExpr() = spec.getAlgoSpec() and
  source.asExpr() = algo and
  MyCryptoFlow::flow(source, sink)
select spec, source, sink, "Cryptographic Algorithm is $@ is used.", algo, algo.getValue()
