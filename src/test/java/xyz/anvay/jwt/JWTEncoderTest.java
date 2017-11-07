package xyz.anvay.jwt;


import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * @author anvaysrivastava
 * @since 07/11/17.
 */
public class JWTEncoderTest {

    private JWTEncoder jwtEncoder;

    public JWTEncoderTest(){}

    @Before
    public void setup(){
        this.jwtEncoder = new JWTEncoder();
    }

    @Test
    public void testSimpleEncodingDecoding(){
        String secret = "Secret";
        String token = jwtEncoder.getEmptyToken(secret);
        Assert.assertNotNull(token);
        Assert.assertTrue(jwtEncoder.isValidToken(secret,token));
    }

}