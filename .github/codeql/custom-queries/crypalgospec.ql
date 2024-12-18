/**
 * @name Use of cryptographic algorithm
 * @description Using  cryptographic algorithms can allow an attacker to compromise security.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.2
 * @precision high
 * @id java/cryptographic-algorithm
 * @tags security
 */

 import java
 import semmle.code.java.security.Encryption
 import semmle.code.java.dataflow.DataFlow
 import semmle.code.java.security.BrokenCryptoAlgorithmQuery
 import InsecureCryptoFlow::PathGraph

 
 abstract class CryptoAlgorithm extends Expr {
    /** Gets the string representation of this insecure cryptographic algorithm. */
    abstract string getStringValue();
  }
  
  private class ShortStringLiteral extends StringLiteral {
    ShortStringLiteral() { this.getValue().length() < 100 }
  }

  class CryptoAlgoLiteral extends CryptoAlgorithm, ShortStringLiteral{
    
    CryptoAlgoLiteral()
    {
        exists(string s | s = this.getValue() | s.length()>1)
    }
    override string getStringValue() { result = this.getValue() }
  }

 from
 DataFlow::Node source, DataFlow::Node sink, CryptoAlgoSpec spec,
    CryptoAlgoLiteral algo
 where
    sink.asExpr() = spec.getAlgoSpec() and
    source.asExpr() = algo and
    DataFlow::localFlow(source, sink)

select
    spec, "Cryptographic algorithm $@ is  used.", algo,
    algo.getStringValue()