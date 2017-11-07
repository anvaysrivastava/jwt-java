package xyz.anvay.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.apache.commons.codec.binary.Base64;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author anvaysrivastava
 * @since 07/11/17.
 */
public class RSAJWTEncoder {

    public String getEmptyToken(PrivateKey privateKey) {
        try {
            Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) privateKey);
            String token = JWT.create()
                    .withIssuer("auth0")
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception) {
            exception.printStackTrace();
        }
        return null;
    }

    public boolean verifyToken(PublicKey publicKey, String token) {
        try {
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("auth0")
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            exception.printStackTrace();
            return false;
            //Invalid signature/claims
        }
    }

    public String getBase64String(Key key) {
        return Base64.encodeBase64String(key.getEncoded());
    }

    public PublicKey getPublicKey(String base64Key) {
        byte[] rawKey = Base64.decodeBase64(base64Key);
        X509EncodedKeySpec ks = new X509EncodedKeySpec(rawKey);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(ks);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public PrivateKey getPrivateKey(String base64Key) {
        byte[] rawKey = Base64.decodeBase64(base64Key);

        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(rawKey);
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(ks);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void printPubPrivKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(512);
        KeyPair kp = kpg.generateKeyPair();
        Key pub = kp.getPublic();
        Key pvt = kp.getPrivate();
        System.out.println("Public: " + getBase64String(pub));
        System.out.println("Private: " + getBase64String(pvt));
    }


}
