import java.math.BigInteger;
import java.util.Random;

import javax.crypto.KeyGenerator;

public class Main {
	
	public BigInteger expMod(BigInteger g, BigInteger a, BigInteger p ) {
		return g.modPow(a, p);
	}
	
	/**
	 * KeyGen() est la fonction qui genere les clefs de Bob
	 * @param p
	 * @param g
	 * @return x clef secrete et X clef publique
	 */
	public BigInteger[] keygen(BigInteger p, BigInteger g) {
		BigInteger x = getRandomBetween(g, p);
		BigInteger gx = expMod(g, x, p);
		BigInteger[] res = {x,gx};
		return res;
	}
	
	public BigInteger[] encrypt(BigInteger p,BigInteger g,BigInteger gx, String m) {
		BigInteger r = getRandomBetween(new BigInteger("2"), p);
		BigInteger y = expMod(gx, r, p);
		BigInteger message = new BigInteger(m.getBytes());
		BigInteger c = y.multiply(message);
		c = c.mod(p);
		BigInteger b = expMod(g, r, p);
		BigInteger[] res = {c,b};
		return res;
	}
	
	public String decrypt(BigInteger p,BigInteger c, BigInteger b, BigInteger x) {
		BigInteger d = expMod(b, x, p);
		d = d.modInverse(p);
		BigInteger decrypt = d.multiply(c);
		decrypt = decrypt.mod(p);
		return new String(decrypt.toByteArray());
	}
	
	public BigInteger getRandomBetween(BigInteger a, BigInteger p) {
		BigInteger res = new BigInteger(1024, new Random());
		if(res.compareTo(a) > 0 && res.compareTo(p.subtract(a)) < 0) {
			return res;
		}else return getRandomBetween(a, p);
	}
	
	public static void main(String[] args) {
		Main m = new Main();
		BigInteger g = new BigInteger("2");
		BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + 
				"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" + 
				"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" + 
				"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" + 
				"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" + 
				"FFFFFFFFFFFFFFFF",16);
		BigInteger[] key =  m.keygen(p, g);
		BigInteger[] eM = m.encrypt(p, g, key[1], "InitialD");
		System.out.println(m.decrypt(p, eM[0], eM[1], key[0]));
	}
	
}
