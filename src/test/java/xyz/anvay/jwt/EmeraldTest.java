package xyz.anvay.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

/**
 * @author anvaysrivastava
 * @since 29/06/18.
 */
public class EmeraldTest {

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private RSAJWTEncoder rsajwtEncoder;

    @Before
    public void populateTestEnv() throws IOException {
        String publicKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3MZkJjcimJrpjfGa37EI1mCuSu+E/gAoWnz9oOESIAvunMoWmELTIoNflL3GAO5DEn+QjE6WMkw9USyCH5spII8VuXaN1aSr2s5DSMa6YsfmiCg9vALYowZqeO57wbRJIUwwKkI5+mFWhtZEYWhvR76pvYTY5stegfhgNdNL5NCL0OWbwhRr0eydRN+2AYmnr8X5eKYHzCopI1oXejDkZ/RKEZflc4qP0xmIkQ5fUAEnCZ/WqPAx4GsoMWWVH/ejbQgEKU2lrwHwjeRXoqp83UcirQ8RlzCQUyr09mvJ0PlBpIYBSwZJghyE0QzFaeHtg9K3Y1hARWmfkv0uqDSILzk3uyyqWWflvO8H/1kFJo3dPLRYWfFLuOemS6kpnVEMY0Svgl9WRCNVCWauJUTD/UTPnNmVm0uHg+9/xJYXr1Dj6FyEAJI+HzN8cvt4+AqHBEBXbk8CB65H9hk+T8Cr9TWqD9fZ6EGGz2ov7ouzOF/VDNM2m/QL7SHcypXKnWO3JilFbCwz217YW+VmZwu1M2LHCjFi3r9m3Czdrsiw5+HGlefuUPGAZIqwqYK5DGZj/HYXJqqTxLgD1qD29saf0O87rGw0EIHQSwonkbRY+Aj3L88wan2VVkdxxRCNKtW1WxKq1od0FDEoVCI/Xbu646JdT8Tj0TrNTCCTjnvTzIMCAwEAAQ==";
        String privateKey = "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";
        rsajwtEncoder = new RSAJWTEncoder();
        this.publicKey = rsajwtEncoder.getPublicKey(publicKey);
        this.privateKey = rsajwtEncoder.getPrivateKeyFromPEMKey(privateKey);
    }

    @Test
    public void validatingAToken() {
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJlbWVyYWxkIiwiaWF0IjoxNTMwMjgwNDc4LCJleHAiOjE1MzAyODE0Nzh9.C3BRy5nFtQ6wos6umxmrGoylLrEqVLPvZ5PgEaVVFhYw3jBOxVIferz0st1TDwfWDmbvy2gJhKnta4UpVF0t-hJLGevMMVFZEZ5pw8VSZb1yDSdRUFuOo8HZuo6Cxb6yW084pyRtuetyKZtiTHsPj96CPxLvO_Txxi4JI2S0D8Yv8jF9ClPnFJHF8Xe5YpyD8bt_Vz4bqYKiPdfovzGFuqdASQ6OpE4KRHVLFpUw67MYznZ-TNYCqMt3yCT1KdRlTdDHrkMPOq2DrAdwcOLvqY56Rle7J5G2SxQA3cpnMOPuFVRy3FVFr8pGkl0aSlcZ6BdBUgt8wENfar2EeE89SkTMVh3MnEcIAkGOAdP7u4mFEXngYBbPdbVhQUueY6Fth2kr8wycn6muOdmKFnNinn-VpSxKhhdKCGc84vpGTEDq-2YSZjuKaK5vnsJ5hqTsUy6-XIosU2MCLSBUCoUpf8Y23kAbwlzoP2AftqdKeMxKhWcR3zVNep9f6f8jyK3X98r3I3tLSwr4h8lfALfnKbcp39pfVZCuZ7EAtORJKyE4cCr0ryeie1FPpya4DnYBX8M7h3djq-eDDlNo8EtaHhJpNnihyxIMEDGgpcblvc3HT0fFu247mpEKnZU3o3Yr-kl0LyLVsxvx0DlzDXIRgMewwY57ab-QhlRsi2sgnUA";
        Boolean isVerified = validSecureToken(publicKey,token);
        Assert.assertTrue(isVerified);
    }

    public boolean validSecureToken(PublicKey publicKey, String secureToken) {
        try {
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build(); //Reusable verifier instance
            DecodedJWT jwt = verifier.verify(secureToken);
            Date issuedAt = jwt.getIssuedAt();
            Date expiry = jwt.getExpiresAt();
            return issuedAt != null && expiry != null && (expiry.getTime() - issuedAt.getTime()) / 1000 <= 1000; // expiry of 1000 seconds
        } catch (JWTVerificationException exception) {
            exception.printStackTrace();
            return false;
        }
    }

}
