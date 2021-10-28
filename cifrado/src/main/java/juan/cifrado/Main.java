package juan.cifrado;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Scanner;

public class Main {

	private static BigInteger N = null;
	private static BigInteger P = null;
	private static BigInteger Q = null;
	private static BigInteger cifrado = null;

	public static void main(String[] args) {
		generaLlaves();
		cifrarMensaje();
		descifrarMensaje();
	}

	public static void generaLlaves() {
		BigInteger[] llaves = Rabin.generarLlaves();
		N = llaves[0];
		P = llaves[1];
		Q = llaves[2];
	}

	public static void cifrarMensaje() {
		System.out.print("Introduce un mensaje: ");
		Scanner sc = new Scanner(System.in);
		String mensaje = sc.nextLine();

		BigInteger m = new BigInteger(mensaje.getBytes(Charset.forName("UTF-8")));
		cifrado = Rabin.cifrar(m, N);

		System.out.println("Cifrado: " + cifrado);
		sc.close();
	}

	public static void descifrarMensaje() {
		BigInteger[] raices = Rabin.descifrar(cifrado, P, Q);
		for (BigInteger raiz : raices) {
			String msjDescifrado = new String(raiz.toByteArray(), Charset.forName("UTF-8"));
			System.out.println("\nDescifrado: " + msjDescifrado);
		}
	}
}
