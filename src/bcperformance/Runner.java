package bcperformance;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.ec.ECElGamalDecryptor;
import org.bouncycastle.crypto.ec.ECElGamalEncryptor;
import org.bouncycastle.crypto.ec.ECPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Runner {
	public static void main(String[] args) {
		int num_runs = 100;
		
		long setup_sum = 0l;
		long keygen_sum = 0l;
		long encrypt_sum = 0l;
		long decrypt_sum = 0l;
		
		for(int i = 0; i < num_runs; i++) {
			long setup_start = System.nanoTime();
			
			X9ECParameters stuff = SECNamedCurves.getByName("secp256k1");
			ECCurve curve = stuff.getCurve();
			
			setup_sum += System.nanoTime() - setup_start;
			
			ECPoint msg_point = stuff.getG().multiply(new BigInteger("13372"));
			
			long keygen_start = System.nanoTime();
			
			ECKeyPairGenerator keygen = new ECKeyPairGenerator();
			ECDomainParameters domain_params = new ECDomainParameters(curve, stuff.getG(), stuff.getN());
			SecureRandom rand = new SecureRandom();
			ECKeyGenerationParameters keygen_params = new ECKeyGenerationParameters(domain_params,rand);
			keygen.init(keygen_params);
			AsymmetricCipherKeyPair keys = keygen.generateKeyPair();
			
			keygen_sum += System.nanoTime() - keygen_start;
			long encrypt_start = System.nanoTime();
			
			ECElGamalEncryptor elgamal_enc = new ECElGamalEncryptor();
			ECPublicKeyParameters pub_params = (ECPublicKeyParameters)keys.getPublic();
			elgamal_enc.init(pub_params);
			ECPair encryption_result = elgamal_enc.encrypt(msg_point);
			
			encrypt_sum += System.nanoTime() - encrypt_start;
			long decrypt_start = System.nanoTime();
			
			ECElGamalDecryptor elgamal_dec = new ECElGamalDecryptor();
			ECPrivateKeyParameters priv_params = (ECPrivateKeyParameters)keys.getPrivate();
			elgamal_dec.init(priv_params);
			ECPoint decryption_result = elgamal_dec.decrypt(encryption_result);
			
			decrypt_sum += System.nanoTime() - decrypt_start;
			
			if(!msg_point.equals(decryption_result)) {
				throw new RuntimeException("Decrypted point not equal to original!");
			}
		
		}
		
		double setup_elapsed = setup_sum/(double)num_runs;
		double keygen_elapsed = keygen_sum/(double)num_runs;
		double encrypt_elapsed = encrypt_sum/(double)num_runs;
		double decrypt_elapsed = decrypt_sum/(double)num_runs;
		
		System.out.println("Setup: "+(setup_elapsed / 1000000d)+" ms");
		System.out.println("Keygen: "+(keygen_elapsed / 1000000d)+" ms");
		System.out.println("Encryption: "+(encrypt_elapsed / 1000000d)+" ms");
		System.out.println("Decryption: "+(decrypt_elapsed / 1000000d)+" ms");
	}
}
