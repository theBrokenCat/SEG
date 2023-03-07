
import java.io.IOException;

/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

import java.util.Scanner;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Principal {

	public static Scanner sc = new Scanner(System.in);
	public static void main (String [] args) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
		int menu1;
		int menu2;
		
		String clave;
		String path;
		String toEncrypt;
		String secretKey;
		String publicKey;
		String signFile;
		String ficheroConFirma;
		String data;
		String fileToVerify;
		// Function to show day 
		do {
			System.out.println("\n\n¿Que tipo de criptograf�a desea utilizar?");
			System.out.println("1. Simetrico.");
			System.out.println("2. Asimetrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
		
			Simetrica sim = new Simetrica();
			//le pasamos el scanner para que pueda usarlo
			Asimetrica asim = new Asimetrica(sc);
			
			switch(menu1){
				case 1:	//SIM�TRICO
					do{
						System.out.println("\n\nElija una opcion para CRIPTOGRAFIA SIMETRICA:");
						System.out.println("0. Volver al menu anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:	//leemos el nombre del fichero y generamos una clave
								System.out.print("\n[+] Escriba el nombre del fichero donde quiere guardar la clave: ");
								String fileName = sc.next();
								System.out.println("\n[+] Clave guardada como: " + fileName);
								
								sim.generarClave(fileName);
							break;
							case 2:	//cifrar
								System.out.print("\n[+] Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("[+] Indique el nombre del fichero a cifrar: ");
								toEncrypt = sc.next();
								System.out.print("[+] Indique donde dejar el fichero cifrado: ");
								path = sc.next();
								
								//File f = new File(fileName);
								
								sim.cifrar(clave, toEncrypt, path);
								
								
							break;
							case 3:	//descifrar
								System.out.print("\n[+] Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("[+] Indique el nombre del fichero a descifrar: ");
								toEncrypt = sc.next();
								System.out.print("[+] Indique donde dejar el fichero descifrado: ");
								path = sc.next();
								
								sim.descifrar(clave, toEncrypt, path);
								
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:	//ASIM�TRICO
					do{
						System.out.println("\n\nElija una opcion para CRIPTOGRAFIA ASIMETRICA:");
						System.out.println("0. Volver al menu anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:	//generación de claves
								System.out.print("\n[+] Indique el nombre del fichero Ks (clave secreta): ");
								secretKey = sc.next();
								System.out.println("[+] Indique el nombre del fichero Kp (clave publica): ");
								publicKey = sc.next();
								
								asim.generarClaves(secretKey, publicKey);
							break;
							case 2:	//cifrado
								System.out.print("\n[+] Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("[+] Indique el nombre del fichero a cifrar: ");
								toEncrypt = sc.next();
								System.out.print("[+] Indique donde dejar el fichero cifrado: ");
								path = sc.next();
								
								asim.cifrar(clave, toEncrypt, path);
								
							break;
							case 3:
								System.out.print("\n[+] Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("[+] Indique el nombre del fichero a descifrar: ");
								toEncrypt = sc.next();
								System.out.print("[+] Indique donde dejar el fichero descifrado: ");
								path = sc.next();
								
								asim.descifrar(clave, toEncrypt, path);
								
							break;
							case 4:
								System.out.print("\n[+] Indique el nombre del fichero Ks (clave secreta): ");
								secretKey = sc.next();
								System.out.print("[+] Indique el nombre del fichero a firmar: ");
								signFile = sc.next();
								System.out.print("[+] Indique el nombre del fichero donde dejar la firma: ");
								ficheroConFirma = sc.next();

								asim.firmar(secretKey, signFile, ficheroConFirma);

							break;
							case 5:
								System.out.print("\n[+] Indique el nombre del fichero Kp (clave publica): ");
								publicKey = sc.next();
								
								System.out.print("[+] Indique el nombre del archivo en claro: ");
								fileToVerify = sc.next();
								
								System.out.print("[+] Indique el nomnbre del fichero que contiene la firma cifrada: ");
								data = sc.next();

								asim.verificar(publicKey, fileToVerify, data);

							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
	
}