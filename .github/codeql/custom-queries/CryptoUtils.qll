import java
import semmle.code.java.security.Encryption

// Abstract class for representing insecure cryptographic algorithms
abstract class CryptoAlgorithm extends Expr {
    /** Gets the string representation of this insecure cryptographic algorithm. */
    abstract string getStringValue();
}

// Represents short string literals used as cryptographic algorithms
private class ShortStringLiteral extends StringLiteral {
    ShortStringLiteral() { this.getValue().length() < 20 }
}

// Represents insecure cryptographic algorithm literals
class CryptoAlgoLiteral extends CryptoAlgorithm, ShortStringLiteral {
    CryptoAlgoLiteral() {
        // Ensure the literal has a meaningful length
        exists(string s | s = this.getValue() | s.length() > 1)
    }

    override string getStringValue() { result = this.getValue() }
}
