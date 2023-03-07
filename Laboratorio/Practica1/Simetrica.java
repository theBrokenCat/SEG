package practica1;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

/*
 * Autores: Adrián Lopez Perez, Arturo Salvador Mayor,
 * 			Fidel Nuñez Friera, Darío Marquez Ibañez
 */
public class Simetrica {

	
	public void generarClave(String fich) throws IOException {
		CipherKeyGenerator ckg = new CipherKeyGenerator();
		ckg.init(new KeyGenerationParameters(new SecureRandom(),256));
		
		byte[] privateKey = Hex.encode(ckg.generateKey());
		
		FileOutputStream salida = new FileOutputStream(fich);
		
		salida.write(privateKey);
		salida.close();
	}
	
	public void cifrar(String keyFile, String fileToEncrypt, String path) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
		// Crea un BufferedReader para leer el archivo keyFile
		BufferedReader br = new BufferedReader(new FileReader(keyFile));
        // Lee una clave hexadecimal
        System.out.println("[+] Clave le�da correctamente");
        
        // Convierte la clave hexadecimal a binario
        byte[] keyBytes = Hex.decode(br.readLine());
        br.close();
        //br.read(); //qu� devuelve?
        
        // Muestra el resultado
        System.out.println("[+] La clave en binario es: " + keyBytes);
        
        
        // Genera par�metros y carga la clave
        KeyParameter params = new KeyParameter(keyBytes);
        
        //crear motor de cifrado con los datos del enunciado
        PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
        
        //iniciar motor de cifrado con params
        cifrador.init(true, params); //true porque cifra
        
        //crear flujos E/S ficheros
        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileToEncrypt));
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(path));
        
        byte[] bloqueEntrada = new byte[cifrador.getBlockSize()];
        byte[] bloqueSalida = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];	//32, para �ltimo bloque 16 mas padding
        
        int bytesLeidos;
        
        while((bytesLeidos = bis.read(bloqueEntrada)) != -1) {
        	int bytesProcesados = cifrador.processBytes(bloqueEntrada, 0, bytesLeidos, bloqueSalida, 0);
        	bos.write(bloqueSalida, 0 , bytesProcesados);
        }
        
        //procesar �ltimo bloque (si es necesario)
        int bytesProcesados = cifrador.doFinal(bloqueSalida, 0);
        bos.write(bloqueSalida, 0, bytesProcesados);
        
        bos.close();
        bis.close();
	}
	
	public void descifrar(String keyFile, String fileToDeEncrypt, String path) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
		// Crea un BufferedReader para leer el archivo keyFile
			BufferedReader br = new BufferedReader(new FileReader(keyFile));
	        // Lee una clave hexadecimal
	        System.out.println("[+] Clave leída correctamente");
	        
	        // Convierte la clave hexadecimal a binario
	        byte[] keyBytes = Hex.decode(br.readLine());
	        br.close();
	        //br.read(); //qu� devuelve?
	        
	        // Muestra el resultado
	        System.out.println("[+] La clave en binario es: " + keyBytes);
	        
	        
	        // Genera par�metros y carga la clave
	        KeyParameter params = new KeyParameter(keyBytes);
	        
	        //crear motor de cifrado con los datos del enunciado
	        PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
	        
	        //iniciar motor de cifrado con params
	        cifrador.init(false, params); //false porque cifra
	        
	        //crear flujos E/S ficheros
			// FileInputStream
	        BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileToDeEncrypt));
	        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(path));
	        
	        byte[] bloqueEntrada = new byte[cifrador.getBlockSize()];
	        byte[] bloqueSalida = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
	        
	        int bytesLeidos;
	        
	        while((bytesLeidos = bis.read(bloqueEntrada)) != -1) {
	        	int bytesProcesados = cifrador.processBytes(bloqueEntrada, 0, bytesLeidos, bloqueSalida, 0);
	        	bos.write(bloqueSalida, 0 , bytesProcesados);
	        }
	        
	        //procesar �ltimo bloque (si es necesario)
	        int bytesProcesados = cifrador.doFinal(bloqueSalida, 0);
	        bos.write(bloqueSalida, 0, bytesProcesados);
	        
	        bos.close();
	        bis.close();
	}
}
