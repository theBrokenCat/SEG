import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
/**
* Clase que implementa el comportamiento necesario para: (1) escribir, peticiones de certificaci�n y (2)certificados X509 en formato PEM. 
* As� como  (3) la clave p�blica y (4) la clave privada en formato PEM.
* @author Seg Red Ser
* @version 1.0
*/
public class GestionObjetosPEM {
	
	public static final String PKCS10_PEM_HEADER = "CERTIFICATE REQUEST";
	public static final String CERTIFICATE_PEM_HEADER = "CERTIFICATE";
	public static final String PKCS8KEY_PEM_HEADER = "PRIVATE KEY";
	public static final String PUBLICKEY_PEM_HEADER = "PUBLIC KEY";
	
	/**
	 * Escribe objeto PEM en un fichero
	 * @param cabecera: String que permite determinar que objeto PEM se va a escribir en el fichero.
	 * Ser�n valores v�lidos para cabecera: "CERTIFICATE REQUEST", "CERTIFICATE", "PRIVATE KEY" y "PUBLIC KEY"
	 * @param datos: byte [] objeto a escribir en formato PEM
	 * @param nombreFichero: String con el nombre del fichero en el que se almacenar� el objeto PEM
	 * @exception IOException si ocurre alguna excepci�n
	 */	
	public static void escribirObjetoPEM (String cabecera, byte []datos, String nombreFichero) throws IOException{
		PemObject po = new PemObject (cabecera, datos);
    		PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(nombreFichero)));
	    	try {
    		 	pemWriter.writeObject(po);
    		} finally {
    			 pemWriter.close();
    		}
  	}
	
	/**
	 * Lee un objeto PEM de un fichero y lo devuelve como un Object
	 * @param fichero: String con el nombre del fichero en el que se encuentra el objeto PEM
	 * @exception FileNotFoundException si no existe el fichero
	 * @exception IOException si ocurre alguna excepci�n
	 */	
	public static Object leerObjetoPEM(String fichero) throws FileNotFoundException, IOException  {
		Object objeto = null;
		PEMParser pemParser;
		pemParser = new PEMParser(new FileReader(fichero));
		objeto = pemParser.readObject();
		pemParser.close();
		
    		return objeto;
	}
}
