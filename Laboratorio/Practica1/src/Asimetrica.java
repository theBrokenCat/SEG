import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.encoders.Hex;


/*
 * Autores: Adrián Lopez Perez, Arturo Salvador Mayor,
 * 			Fidel Nuñez Friera, Darío Marquez Ibañez
 */
public class Asimetrica {

	private Scanner sc;
	private boolean esFirma;
	private boolean esVerificacion;
	public Asimetrica(Scanner sc) {
		this.sc = sc;
		esFirma = false;	//ya que antes de firmar no se ha firmado nada
		esVerificacion = false;	//ya que antes de verificar no se ha verificado nada
	}

	/* Función para generar un par de claves RSA
	 * @param secretKey nombre del fichero donde se guardará la clave privada
	 * @param publicKey nombre del fichero donde se guardará la clave pública
	 */
	public void generarClaves(String secretKey, String publicKey) {
		GuardarFormatoPEM pem = new GuardarFormatoPEM();
		/*
		 * creamos param, que se utiliza para especificar los parámetros necesarios para la generación de un par de claves RSA
		 * 3 indica que el valor del primo pequeño se establece en 3
		 * SecureRandom() indica que se utiliza un generador de números aleatorios seguro
		 * 2048 indica que el tamaño de la clave es de 2048 bits
		 * 10 indica la probabilidad de que el número generado sea primo. en este caso es 10,
		 * lo que significa que la probabilidad de que el número generado sea primo es 1/2^10
		 */
		RSAKeyGenerationParameters param = new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), 2048, 10);
		//creamos un generador de claves RSA
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		//inicializamos el generador de claves con los parámetros especificados
		generadorClaves.init(param);
		//generamos el par de claves, AsymmetricCipherKeyPair es una clase que contiene un par de claves
		AsymmetricCipherKeyPair ackp = generadorClaves.generateKeyPair();
		
		pem.guardarClavesPEM(ackp.getPublic(), ackp.getPrivate());

		//obtenemos la clave privada y la clave pública a partir del par de claves ackp
		RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters) ackp.getPrivate();
		RSAKeyParameters pub = (RSAKeyParameters) ackp.getPublic();

		try {
			//escribimos la clave privada en el fichero llamado secretKey
			PrintWriter fichPrivada = new PrintWriter(new FileWriter(secretKey));
			
			/*
			fichPrivada.println(new String(priv.getModulus().toByteArray()));					es menos exacto, pero POR QUÉ?
			priv.getModulus().toByteArray() devuelve el valor en binario, por lo que puede llegar a ser más largo que el valor en hexadecimal,
			y dependiendo de la máquina, lo podrá entender de una forma u otra, por lo que puede que no se pueda leer correctamente
			usando Hex.encode() lo convertimos a hexadecimal, y así no hay problema
			*/
			fichPrivada.println(new String(Hex.encode(priv.getModulus().toByteArray())));
			fichPrivada.print(new String(Hex.encode(priv.getExponent().toByteArray())));
			fichPrivada.close();
			
			//escribimos la clave pública en el fichero llamado publicKey
			PrintWriter fichPub = new PrintWriter(new FileWriter(publicKey));

			fichPub.println(new String(Hex.encode(pub.getModulus().toByteArray())));
			fichPub.println(new String(Hex.encode(pub.getExponent().toByteArray())));
			fichPub.close();
			
		}catch(FileNotFoundException e) {
			e.printStackTrace();
		}catch(IOException e) {
			e.printStackTrace();
		}
	}
	
	
	/* Cifra el fichero toEncrypt con la clave privada o publica indicada en el
	 * fichero clave y escribe el resultado en el fichero encrypted
	 * 
	 * @param clave Fichero que contiene la clave privada o publica
	 * 
	 * @param toEncrypt Fichero que contiene los datos a cifrar
	 * 
	 * @param encrypted Fichero donde se escribiran los datos cifrados
	 */
	public void cifrar(String clave, String toEncrypt, String encrypted) throws IOException, InvalidCipherTextException {
		BufferedReader lectorClave = new BufferedReader(new FileReader(clave));	//Leo la clave
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));	//Leo el modulo de la clave
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));	//Leo el exponente de la clave
		lectorClave.close();

		// se crea un cifrador RSA con codificación PKCS1
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());

		// comprobamos si se ha ejecutado el metodo de firmar o no
		if(!esFirma){
			System.out.print("[+] Detalle, quiere usar clave privada(1) o publica(0): ");
			String tipo = sc.next();

			// se crean los parámetros necesarios para inicializar un cifrador RSA de clave
			// privada o publica. 1 para privada, 0 para publica
			RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("1"), modulo, exponente);
			// se inicializa el cifrador, true para cifrar, false para descifrar
			cifrador.init(true, parametros);
		}else{
			esFirma = false;	//se vuelve a poner a false para que la siguiente vez que se ejecute el metodo, no se entre en este if
			// al tratarse de una firma, se usa la clave privada
			RSAKeyParameters parametros = new RSAKeyParameters(true, modulo, exponente);
			// se inicializa el cifrador, true para cifrar, false para descifrar
			cifrador.init(true, parametros);
		}
		
		
		//creamos los buffers de entrada y salida
		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(toEncrypt));
	            BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(encrypted))) {
			//creamos los arrays de bytes que contendrán los datos leidos y los datos cifrados
	        byte[] datosLeidos = new byte[cifrador.getInputBlockSize()];	//el tamaño del array de bytes es el tamaño del bloque de entrada del cifrador
	        byte[] datosCifrados;
	        int leidos;

	        // Leer bloques del archivo de entrada y cifrarlos
	        while ((leidos = entrada.read(datosLeidos)) != -1) {
	            datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);
	            salida.write(datosCifrados);
	        }
	        salida.close();
	        entrada.close();
	     }
		
	}

	/*
	 * Descifra el fichero toDecrypt con la clave privada o publica indicada en el
	 * fichero clave y escribe el resultado en el fichero decrypted
	 * 
	 * @param clave Fichero que contiene la clave privada o publica
	 * 
	 * @param toDecrypt Fichero que contiene los datos a descifrar
	 * 
	 * @param decrypted Fichero donde se escribiran los datos descifrados
	 */
	public void descifrar(String clave, String toDecrypt, String decrypted) throws IOException, InvalidCipherTextException {
	    BufferedReader lectorClave = new BufferedReader(new FileReader(clave));
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
		lectorClave.close();

		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		if(!esVerificacion){
			System.out.print("[+] Detalle, quiere usar clave privada(1) o publica(0): ");
			String tipo = sc.next();
			// privada o publica. 1 para privada, 0 para publica
			RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("1"), modulo, exponente);
			cifrador.init(false, parametros);
		}else {
			esVerificacion = false;
			// al tratarse de una verificacion, se usa la clave publica
			RSAKeyParameters parametros = new RSAKeyParameters(false, modulo, exponente);
			cifrador.init(false, parametros);
		}

		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(toDecrypt));
				BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(decrypted))) {
			byte[] datosLeidos = new byte[cifrador.getInputBlockSize()];
			byte[] datosCifrados;
			int leidos;

			// Leer bloques del archivo de entrada y cifrarlos
			/*
			 * datosLeidos es un array vacío de tamaño igual al tamaño del bloque de entrada del cifrador
			 * leidos es el número de bytes leídos del fichero de entrada
			 * 
			 * datosLeidos cuando usamos el método entrada.read(datosLeidos) se rellena con los bytes leídos
			 * del fichero de entrada (lee tantos bytes como el tamaño de datosLeidos sea y además a este le asigna el valor de los bytes leídos)
			 */
			while ((leidos = entrada.read(datosLeidos)) != -1) {
				/* cifrador.processBlock lo que hace es coger los tantos bytes como leidos, cifrarlos 
				 * y devolverlos dentro de datosLeidos
				 * 
				*/
				datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);
				salida.write(datosCifrados);
			}
			salida.close();
			entrada.close();
		}
	}
	

	/*
	 * @param clave Fichero que contiene la clave secreta
	 * @param mensajeEnClaro fichero que contiene el mensaje que desea firmar
	 * @param nombreFirma fichero donde se guardará la firma
	 */
	public void firmar(String clave, String mensajeEnClaro, String nombreFirma)
			throws IOException, InvalidCipherTextException {
		Digest resumen = new SHA3Digest();
		// generar el resumen: los bloques de lectura son del mismo tamaño que el resumen
		byte[] datosLeidos = new byte[resumen.getDigestSize()];
		byte[] datosFirmados = new byte[resumen.getDigestSize()];

		BufferedInputStream enClaro = new BufferedInputStream(new FileInputStream(mensajeEnClaro));
		int leidos;
		// bucle de lectura de bloques del fichero con método update
		while ((leidos = enClaro.read(datosLeidos)) != -1) {
			resumen.update(datosLeidos, 0, leidos);
		}
		//finalizar la operación de resumen
		resumen.doFinal(datosFirmados, 0);
		enClaro.close();

		/*
		PARA BORRAR PORQUE NO ES NECESARIO
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(nombreFirma+".hash"));
		out.write(datosFirmados);
		out.close();
		*/
		esFirma = true;
		cifrar(clave, mensajeEnClaro, nombreFirma);
	}

	/*
	 * @param clave fichero con la clave secreta para firmar
	 * @param toVerificar fichero que contiene el mensaje que desea verificar
	 * @param archivo fichero en claro
	 */
	public void verificar(String clave, String toVerificar, String archivo) throws InvalidCipherTextException{
		//generar el resumen del texto en claro igual que en el método firmar, pero este método deja en un byte[] el resumen
		Digest resumen = new SHA3Digest();
		byte[] datosLeidos = new byte[resumen.getDigestSize()];
		byte[] datosFirmados = new byte[resumen.getDigestSize()];
		try {
			BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(toVerificar));
			int leidos;
			while ((leidos = entrada.read(datosLeidos)) != -1) {
				resumen.update(datosLeidos, 0, leidos);
			}
			resumen.doFinal(datosFirmados, 0);
			entrada.close();

			esVerificacion = true;
			// descifrar el fichero que contiene la firma (toVerificar) y almacenar el resultado en un fichero temporal
			descifrar(clave, toVerificar, "temporal");
			//leer el fichero temporal y almacenar el contenido en un byte[] llamado fd
			BufferedInputStream entrada2 = new BufferedInputStream(new FileInputStream("temporal"));
			BufferedInputStream textoClaro = new BufferedInputStream(new FileInputStream(archivo));
			byte[] fd = new byte[entrada2.available()];
			byte[] original = new byte[textoClaro.available()];
			entrada2.read(fd);
			textoClaro.read(original);
			entrada2.close();
			textoClaro.close();
			//comparar los dos resúmenes y devolver true o false
			if (Arrays.equals(original, fd)) {
				System.out.println("\n[+] La firma es correcta");
			} else {
				System.out.println("\n[+] La firma no es correcta");
			}

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	
}
