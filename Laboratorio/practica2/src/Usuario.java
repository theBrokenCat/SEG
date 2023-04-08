import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.operator.OperatorCreationException;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;


/**
* Esta clase implementa el comportamiento de un usuario en una Infraestructura de Certificaci�n
* @author Seg Red Ser
* @version 1.0
*/
public class Usuario {

	private RSAKeyParameters clavePrivada = null;
	private RSAKeyParameters clavePublica = null;


	/**
	 * M�todo que genera las claves del usuario.
	 * @param fichClavePrivada: String con el nombre del fichero donde se guardar� la clave privada en formato PEM
	 * @param fichClavePublica: String con el nombre del fichero donde se guardar� la clave publica en formato PEM
     * @throws IOException 	
	
	 */
	public void generarClavesUsuario (String fichClavePrivada, String fichClavePublica) throws IOException{
		GestionClaves gc = new GestionClaves (); 
		// Escribir las claves en un fichero en formato PEM 
		AsymmetricCipherKeyPair claves = gc.generarClaves(BigInteger.valueOf(3), 2048);
		clavePrivada = (RSAKeyParameters) claves.getPrivate();
		clavePublica = (RSAKeyParameters) claves.getPublic();
		PrivateKeyInfo clavePrivadaInfo = gc.getClavePrivadaPKCS8(clavePrivada);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS8KEY_PEM_HEADER, clavePrivadaInfo.getEncoded(), fichClavePrivada);
		SubjectPublicKeyInfo clavePublicaInfo = gc.getClavePublicaSPKI(clavePublica);
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PUBLICKEY_PEM_HEADER, clavePublicaInfo.getEncoded(), fichClavePublica);
    }



	
	/**
	 * M�todo que genera una petici�n de certificado en formato PEM, almacenando esta petici�n en un fichero.
	 * @param fichPeticion: String con el nombre del fichero donde se guardar� la petici�n de certificado
	 * @throws IOException 
	 * @throws OperatorCreationException 
	 */
	public void crearPetCertificado(String fichPeticion) throws OperatorCreationException, IOException {
		// IMPLEMENTAR POR EL ESTUDIANTE
 
	   	// Configurar hash para resumen y algoritmo firma (MIRAR DIAPOSITIVAS PRESENTACI�N PR�CTICA)
		// La solicitud se firma con la clave privada del usuario y se escribe en fichPeticion en formato PEM
		
		// generamos el nombre x500 del propietario
		X500Name nombrePropietario = new X500Name("C=ES, O=DTE, CN=Pepito");
		GestionClaves gc = new GestionClaves();
		SubjectPublicKeyInfo clavePublica = gc.getClavePublicaSPKI(this.clavePublica);
		PKCS10CertificationRequestBuilder requestBuilder = new PKCS10CertificationRequestBuilder(nombrePropietario, clavePublica);

		// generamos la solicitud de certificado
		DefaultSignatureAlgorithmIdentifierFinder sigAlgFinder = new DefaultSignatureAlgorithmIdentifierFinder();
		// generamos el algoritmo de firma
		DefaultDigestAlgorithmIdentifierFinder digAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();
		// generamos el algoritmo de resumen
		AlgorithmIdentifier sigAlgId = sigAlgFinder.find("SHA256withRSA");
		// usamos el algoritmo de firma
		AlgorithmIdentifier digAlgId = digAlgFinder.find(sigAlgId);
		BcContentSignerBuilder csBuilder = new BcRSAContentSignerBuilder(sigAlgId, digAlgId);

		// generamos la peticion de certificado
		PKCS10CertificationRequest pet = requestBuilder.build(csBuilder.build(this.clavePrivada));

		// guardamos pet en fichero en formato PEM
		GestionObjetosPEM.escribirObjetoPEM(GestionObjetosPEM.PKCS10_PEM_HEADER, pet.getEncoded(), fichPeticion);
		
	}
	
	
	/**
	 * M�todo que verifica un certificado de una entidad.
	 * @param fichCertificadoCA: String con el nombre del fichero donde se encuentra el certificado de la CA
	 * @param fichCertificadoUsu: String con el nombre del fichero donde se encuentra el certificado de la entidad
     	 * @throws CertException 
	 * @throws OperatorCreationException 
	 * @throws IOException 
	 * @throws FileNotFoundException 	
	 * @return boolean: true si verificaci�n OK, false en caso contrario.
	 */
    public boolean verificarCertificadoExterno(String fichCertificadoCA, String fichCertificadoUsu)throws OperatorCreationException, CertException, FileNotFoundException, IOException {

    // IMPLEMENTAR POR EL ESTUDIANTE
	// Comprobar fecha validez del certificado
	// Si la fecha es v�lida, se comprueba la firma
	// Generar un contenedor para la verificaci�n con la clave p�blica de CA,
	// el certificado del usuario tiene el resto de informaci�n
    	
   	// IMPLEMENTAR POR EL ESTUDIANTE
  		X509CertificateHolder certUsuario = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoUsu);
		//comparamos la fecha de validez del certificado con la fecha actual
		Date fechaActual = new Date();
		if (fechaActual.before(certUsuario.getNotBefore()) || fechaActual.after(certUsuario.getNotAfter())) {
			return false;
		} else {
			GestionClaves gc = new GestionClaves();
			// comprobamos la firma del certificado
			X509CertificateHolder certCA = (X509CertificateHolder) GestionObjetosPEM.leerObjetoPEM(fichCertificadoCA);
			//Obtener clave pública de la CA en formato RSAKeyParameters
			SubjectPublicKeyInfo clavePublicaCAInfo = certCA.getSubjectPublicKeyInfo();
			RSAKeyParameters clavePublicaCA = gc.getClavePublicaMotor(clavePublicaCAInfo);

			// Generar un contenedor para la verificación con la clave pública de CA
			ContentVerifierProvider contentVerifierProvider = new BcRSAContentVerifierProviderBuilder(new DefaultDigestAlgorithmIdentifierFinder()).build(clavePublicaCA);
			// Verificar firma del certificado
			return certUsuario.isSignatureValid(contentVerifierProvider);

		}
		

	}	
}
