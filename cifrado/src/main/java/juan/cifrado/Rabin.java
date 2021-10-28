package juan.cifrado;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Rabin {

	private static final BigInteger DOS = BigInteger.valueOf(2);
	private static final BigInteger TRES = BigInteger.valueOf(3);
	private static final BigInteger CUATRO = BigInteger.valueOf(4);
	private static final int BITS_PK = 512;

	private Rabin() {
	}

	/**
	 * Genera una llave publica y llaves privadas
	 * 
	 * @return Array de BigIntegers {N,p,q}. N es la llave publica, p y q son las
	 *         llaves privadas
	 */
	public static BigInteger[] generarLlaves() {
		BigInteger p = primoAleatorio();
		BigInteger q = primoAleatorio();
		BigInteger N = p.multiply(q);
		return new BigInteger[] { N, p, q };
	}

	/**
	 * Cifra un valor con la llave publica (N)
	 * 
	 * @param m valor a cifrar
	 * @param N la llave publica (N)
	 * @return valor cifrado
	 */
	public static BigInteger cifrar(BigInteger m, BigInteger N) {
		return m.modPow(DOS, N);
	}

	/**
	 * Descifra un valor con las llaves privadas (p y q)
	 * 
	 * @param c numero cifrado
	 * @param p llave privada
	 * @param q llave privada
	 * @return Array de 4 posibles descifrados
	 */
	public static BigInteger[] descifrar(BigInteger c, BigInteger p, BigInteger q) {
		BigInteger N = p.multiply(q);

		BigInteger r = c.modPow(p.add(BigInteger.ONE).divide(CUATRO), p);
		BigInteger s = c.modPow(q.add(BigInteger.ONE).divide(CUATRO), q);

		BigInteger[] ext = euclidianoExtendido(p, q);
		BigInteger a = ext[0];
		BigInteger b = ext[1];

		// (a * p * s + (b * q * r)) mod N
		BigInteger m1 = a.multiply(p).multiply(s).add(b.multiply(q).multiply(r)).mod(N);
		// (a * p * s + (b * q * (p - r))) mod N
		BigInteger m2 = a.multiply(p).multiply(s).add(b.multiply(q).multiply(p.subtract(r))).mod(N);
		// (a * p * (q - s) + (b * q * r)) mod N
		BigInteger m3 = a.multiply(p).multiply(q.subtract(s)).add(b.multiply(q).multiply(r)).mod(N);
		// (a * p * (q - s) + (b * q * (p - r))) mod N
		BigInteger m4 = a.multiply(p).multiply(q.subtract(s)).add(b.multiply(q).multiply(p.subtract(r))).mod(N);

		return new BigInteger[] { m1, m3, m2, m4 };
	}

	/**
	 * Genera un algoritmo euclidiano extendido para obtener los coeficientes de la
	 * identidad de Bézout
	 * 
	 * @return Array de BigInteger, donde encontraremos los coeficientes a y b
	 */
	private static BigInteger[] euclidianoExtendido(BigInteger a, BigInteger b) {
		BigInteger aa = a;
		BigInteger bb = b;
		BigInteger x = BigInteger.ZERO;
		BigInteger lasty = BigInteger.ZERO;
		BigInteger temp;
		BigInteger y = BigInteger.ONE;
		BigInteger lastx = BigInteger.ONE;

		while (!bb.equals(BigInteger.ZERO)) {
			BigInteger q = aa.divide(bb);
			BigInteger r = aa.mod(bb);

			aa = bb;
			bb = r;

			temp = x;
			x = lastx.subtract(q.multiply(x));
			lastx = temp;

			temp = y;
			y = lasty.subtract(q.multiply(y));
			lasty = temp;
		}
		return new BigInteger[] { lastx, lasty };
	}

	/**
	 * Genera un numero aleatorio tal que: p≡3 (mod 4) con un especificado numero de
	 * bits
	 * 
	 * @return BigInteger: Numero primo aleatorio
	 */
	private static BigInteger primoAleatorio() {
		BigInteger p;
		do {
			p = BigInteger.probablePrime(BITS_PK, new SecureRandom());
		} while (!p.mod(CUATRO).equals(TRES));
		return p;
	}

}
