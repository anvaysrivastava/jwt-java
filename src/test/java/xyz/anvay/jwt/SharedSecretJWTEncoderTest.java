package xyz.anvay.jwt;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author anvaysrivastava
 * @since 07/11/17.
 */
public class SharedSecretJWTEncoderTest {

    private SharedSecretJWTEncoder jwtEncoder;

    public SharedSecretJWTEncoderTest() {
    }

    @Before
    public void setup() {
        this.jwtEncoder = new SharedSecretJWTEncoder();
    }

    @Test
    public void testSimpleEncodingDecoding() {
        String secret = "Secret";
        String token = jwtEncoder.getEmptyToken(secret);
        Assert.assertNotNull(token);
        Assert.assertTrue(jwtEncoder.isValidToken(secret, token));
    }

    @Test
    public void testTimeSensitivity() throws InterruptedException {
        String secret = "Secret";
        String token = jwtEncoder.getTimeSensitiveEmptyToken(secret, 2000);
        System.out.println(token);
        Assert.assertTrue(jwtEncoder.isValidToken(secret, token));
        Thread.sleep(5000);
        Assert.assertFalse(jwtEncoder.isValidToken(secret, token));
    }

}