package xyz.anvay.jwt;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author anvaysrivastava
 * @since 07/11/17.
 */
public class RSAJWTEncoderTest {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private RSAJWTEncoder rsajwtEncoder;

    @Before
    public void populateTestEnv() {
        String publicKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANGcAU4p34cxJbkY4gZfdnfWEJNtQM+xStv98z1y430aHve18XtZDQ4arZbEchhhkWwy398HtnbBjcXRp/dpqlsCAwEAAQ==";
        String privateKey = "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA0ZwBTinfhzEluRjiBl92d9YQk21Az7FK2/3zPXLjfRoe97Xxe1kNDhqtlsRyGGGRbDLf3we2dsGNxdGn92mqWwIDAQABAkEAxua/wlkvuIzlnABFswBxXYPvVMZuouc8/wa7A4t63WDsJlXnY3ANO/Qx1bq+LB9sFtA0mQiHdxNxAqa38HfHwQIhAPohrvPEOMNBitOhJy+cGfnloupdY+ai5LYCG4BG+Dy7AiEA1obw8s0XAcf6f33ldpaeW7ddvHi2/ygLjmu007ylPuECIBRR4DCVZDcYf/qpQNGxULroWM/JPnBiE0pl6W4GVew5AiEAk1F1c3ctfnai6hw9kJNcSiWAxGWtXUlVrkb+lYzteWECIHgR2xbtvn9/TUft64oOImccdy7mnGHySw9v2GmeMl0F";
        rsajwtEncoder = new RSAJWTEncoder();
        this.publicKey = rsajwtEncoder.getPublicKey(publicKey);
        this.privateKey = rsajwtEncoder.getPrivateKey(privateKey);

    }

    @Test
    public void printPubPrivateKeys() throws NoSuchAlgorithmException {
        RSAJWTEncoder rsajwtEncoder = new RSAJWTEncoder();
        rsajwtEncoder.printPubPrivKeys();
    }

    @Test
    public void testBasicTokenGeneration() {
        String token = rsajwtEncoder.getEmptyToken(privateKey);
        Assert.assertNotNull(token);
        System.out.println(token);
    }

    @Test
    public void validatingAToken() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.YGiR4ATaLXA-GreW6Yzi6QkyE4JF3ZymZBKftTfx2yzb1eUvV68onxbCIX36NiaRbSDI4kvCENoakuB0C2EBeA";
        Assert.assertTrue(rsajwtEncoder.verifyToken(publicKey, token));
    }

    @Test
    public void validateWrongKeyFailure() {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJhdXRoMCJ9.YGiR4ATaLXA-GreW6Yzi6QkyE4JF3ZymZBKftTfx2yzb1eUvV68onxbCIX36NiaRbSDI4kvCENoakuB0C2EBeA";
        String otherPublicStringKey = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKJY80SX+/CvYQd0HkT9hYz2ODyKZA2aWZqOm/pBitvSdFmghxqvaucUaa+FydDDSZC93B9nq+hZjEIqb2VPmUMCAwEAAQ==";
        PublicKey otherPublicKey = rsajwtEncoder.getPublicKey(otherPublicStringKey);
        Assert.assertFalse(rsajwtEncoder.verifyToken(otherPublicKey, token));
    }

}
