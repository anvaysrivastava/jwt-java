package xyz.anvay.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.util.Date;

/**
 * @author anvaysrivastava
 * @since 07/11/17.
 */
public class SharedSecretJWTEncoder {

    public SharedSecretJWTEncoder(){

    }

    public String getEmptyToken(String secret){

        try{
            Algorithm algorithm = Algorithm.HMAC512(secret);

            return JWT.create().withIssuer("Issuer").sign(algorithm);

        } catch (UnsupportedEncodingException e){
            //Thrown only when UTF-8 is being encoded.
            e.printStackTrace();
            return null;
        }
    }

    public String getTimeSensitiveEmptyToken(String secret,long expiryTimeInMillis){
        try{
            Algorithm algorithm = Algorithm.HMAC512(secret);
            long expiryepoch = new Date().getTime() + expiryTimeInMillis;
            return JWT.create().withIssuer("Issuer").withExpiresAt(new Date(expiryepoch)).sign(algorithm);
        } catch (UnsupportedEncodingException e){
            //Thrown only when UTF-8 is being encoded.
            e.printStackTrace();
            return null;
        }
    }

    public boolean isValidToken(String secret, String token){
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .acceptLeeway(0)
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(token);
            return  true;
        } catch (UnsupportedEncodingException exception){
            //UTF-8 encoding not supported
            exception.printStackTrace();
            return false;
        } catch (TokenExpiredException exception){
            return false;
        } catch (JWTVerificationException exception){
            //Invalid signature/claims
            exception.printStackTrace();
            return false;
        }
    }

}
