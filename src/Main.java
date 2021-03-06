import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

public class Main {

	public BigInteger[] euclide(BigInteger a, BigInteger p){
		BigInteger[] q = {null,null};
		BigInteger u,v;
		if(p.equals(BigInteger.ZERO)){
			q[0] = BigInteger.ONE;
			q[1] = BigInteger.ZERO;
			return q;
		}
		q = euclide(p,a.mod(p));
		u = q[1];
		v = q[0];
		q[0] = u;
		q[1] = v.subtract(u.multiply(a.divide(p)));
		
		//BigInteger[] res = {u,v}; 
		return q;
	}
	
	public BigInteger expMod(BigInteger g, BigInteger a, BigInteger p) {
		return g.modPow(a, p);
	}

	/**
	 * KeyGen() est la fonction qui genere les clefs de Bob
	 * 
	 * @param p
	 * @param g
	 * @return x clef secrete et X clef publique
	 */
	public BigInteger[] keygen(BigInteger p, BigInteger g) {
		BigInteger x = getRandomBetween(g, p);
		BigInteger gx = expMod(g, x, p);
		BigInteger[] res = { x, gx };
		return res;
	}

	public BigInteger[] encrypt(BigInteger p, BigInteger g, BigInteger gx, String m) {
		BigInteger r = getRandomBetween(g, p);
		BigInteger y = expMod(gx, r, p);
		BigInteger message = new BigInteger(m.getBytes());
		BigInteger c = y.multiply(message);
		c = c.mod(p);
		BigInteger b = expMod(g, r, p);
		BigInteger[] res = { c, b, r };
		return res;
	}

	public String decrypt(BigInteger p, BigInteger c, BigInteger b, BigInteger x) {
		BigInteger d = expMod(b, x, p);
		d = d.modInverse(p);
		BigInteger decrypt = d.multiply(c);
		decrypt = decrypt.mod(p);
		return new String(decrypt.toByteArray());
	}

	public BigInteger getRandomBetween(BigInteger a, BigInteger p) {
		BigInteger res = new BigInteger(1024, new SecureRandom());
		if (res.compareTo(a) > 0 && res.compareTo(p.subtract(a)) < 0) {
			return res;
		} else
			return getRandomBetween(a, p);
	}

	public static void main(String[] args) throws FileNotFoundException {
		Main m = new Main();
		BigInteger g = new BigInteger("2");
		BigInteger p = new BigInteger(
				"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
						+ "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
						+ "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
						+ "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" + "FFFFFFFFFFFFFFFF",
				16);

		// Fichier de sortie
		File file = new File("test.txt");
		PrintWriter pw = new PrintWriter(file);
		//Question 3 
		pw.println();
		pw.println("***********************QUESTION 3************************");
		
		BigInteger a,pgcd;
		BigInteger[] euclide;
		for(int i = 1;i<10000;i++){
			a = new BigInteger(Integer.toString(i));
			euclide = m.euclide(a, p);
			pgcd = a.multiply(euclide[0]).add(p.multiply(euclide[1]));
			pw.println("Fonction Euclide: a="+a);
			pw.println("r avec Euclide:"+pgcd+" : r avec fonction gcd : "+a.gcd(p));
			if(!pgcd.equals(a.gcd(p))){
				System.out.println("erreur : "+i);
				break;
			}
		}
		// Question4
		pw.println();
		pw.println("***********************QUESTION 4************************");
		for (int i = 0; i < 10000; i++) {
			pw.println("Valeur de a : " + i + ", ExpMod(): " + m.expMod(g, new BigInteger(Integer.toString(i)), p));
		}
		pw.println();
		pw.println();
		pw.println();

		// Question5
		pw.println("***********************QUESTION 5************************");
		int compteurR = 0;
		ArrayList<BigInteger> r = new ArrayList<BigInteger>();
		for (int i = 0; i < 100; i++) {
			String message = "Message secret num :" + i;
			BigInteger[] key = m.keygen(p, g);
			BigInteger[] eM = m.encrypt(p, g, key[1], message);
			String res = m.decrypt(p, eM[0], eM[1], key[0]);
			pw.println("r : " + eM[2] + ", Message de depart '" + message + "', Decrypte '" + res + "'");
			if (r.contains(eM[2])) {
				compteurR++;
			} else
				r.add(eM[2]);
		}
		pw.println("Nombre de r similaires : " + compteurR);
		pw.println();
		pw.println();
		pw.println();

		// Question6
		pw.println("***********************QUESTION 6************************");
		String m1 = "Winter";
		String m2 = "IsComing!";
		pw.println(m1);
		pw.println(m2);
		
		BigInteger[] key = m.keygen(p, g);
		BigInteger[] encryptM1 = m.encrypt(p, g, key[1], m1);
		BigInteger[] encryptM2 = m.encrypt(p, g, key[1], m2);

		//c
		BigInteger c = encryptM1[0].multiply(encryptM2[0]);
		c = c.mod(p);

		//B
		BigInteger b = encryptM1[1].multiply(encryptM2[1]);
		b = b.mod(p);
		String res = m.decrypt(p, c, b, key[0]);
		
		BigInteger decryptM1 = new BigInteger(m1.getBytes());
		BigInteger decryptM2 = new BigInteger(m2.getBytes());
		BigInteger decryptM = new BigInteger(res.getBytes());
		BigInteger produitM1M2modP = decryptM1.multiply(decryptM2);
		produitM1M2modP = produitM1M2modP.mod(p);

		pw.println("m=m1 m2 mod p");
		pw.println(decryptM + " = " + produitM1M2modP);
		pw.close();
	}

}
