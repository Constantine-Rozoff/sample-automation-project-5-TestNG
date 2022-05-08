package net.absoft;

import net.absoft.data.Response;
import net.absoft.services.AuthenticationService;
import org.testng.annotations.Test;
import org.testng.asserts.SoftAssert;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class AuthenticationServiceTest {

    @Test
    public void testSuccessfulAuthentication() {
        Response response = new AuthenticationService().authenticate("user1@test.com", "password1");
        assertEquals(response.getCode(), 200, "Response code should be 200");
        assertTrue(validateToken(response.getMessage()), "Token should be the 32 digits string. Got " + response.getMessage());
    }

    @Test
    public void testAuthenticationWithWrongPassword() {
        validateErrorResponse(new AuthenticationService().authenticate("user1@test.com", "wrong_password1"),
                401,
                "Invalid email or password");
    }

    @Test
    public void testAuthenticationWithEmptyEmail() {
        Response expectedResponse = new Response(400, "Email should not be empty string");
        Response actualResponse = new AuthenticationService().authenticate("", "password1");
        assertEquals(actualResponse, expectedResponse, "Unexpected response");
    }

    @Test
    public void testAuthenticationWithInvalidEmail() {

    }

    @Test
    public void testAuthenticationWithEmptyPassword() {

    }

    private boolean validateToken(String token) {
        final Pattern pattern = Pattern.compile("\\S{32}", Pattern.MULTILINE);
        final Matcher matcher = pattern.matcher(token);
        return matcher.matches();
    }

    private void validateErrorResponse(Response response, int code, String message) {
        SoftAssert softAssert = new SoftAssert();
        softAssert.assertEquals(response.getCode(), code, "Response code should be 401");
        softAssert.assertEquals(response.getMessage(), message, "Response message should be \"Invalid email or password\"");
        softAssert.assertAll();
    }
}