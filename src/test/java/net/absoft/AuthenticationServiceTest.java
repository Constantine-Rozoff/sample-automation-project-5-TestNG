package net.absoft;

import net.absoft.data.Response;
import net.absoft.services.AuthenticationService;
import org.testng.annotations.*;
import org.testng.asserts.SoftAssert;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class AuthenticationServiceTest {

    private AuthenticationService authenticationService;
    private String message;

    public AuthenticationServiceTest(String message) {
        this.message = message;
    }

    @BeforeClass(
            groups = "negative"
    )
    public void setUp() {
        authenticationService = new AuthenticationService();
    }

    @Test(
            description = "Test successful authentication",
            groups = "positive"
    )
    @Parameters({"email-address", "password"})
    public void testSuccessfulAuthentication(String email, String password) {
        Response response = authenticationService.authenticate(email, password);
        assertEquals(response.getCode(), 200, "Response code should be 200");
        assertTrue(validateToken(response.getMessage()), "Token should be the 32 digits string. Got " + response.getMessage());
    }

    @Test(
            groups = "negative"
    )
    @Parameters({"email-address", "password"})
    public void testAuthenticationWithWrongPassword(@Optional("user1@test.com") String email,@Optional("password1") String password) {
        validateErrorResponse(authenticationService.authenticate(email, password),
                401,
                "Invalid email or password");
        System.out.println("testAuthenticationWithWrongPassword " + message);
    }

    @DataProvider(name = "invalidLogins")
    public Object[][] invalidLogins() {
        return new Object[][] {
                new Object[] {"user1@test.com", "wrong_password1", new Response(401, "Invalid email or password")},
                new Object[] {"", "password1", new Response(400, "Email should not be empty string")}
        };
    }

    @Test(
            priority = 3,
            groups = "negative",
            dataProvider = "invalidLogins"
    )
    public void testAuthenticationWithEmptyEmail(String email, String password, Response expectedResponse) {
        //Response expectedResponse = new Response(400, "Email should not be empty string");
        Response actualResponse = authenticationService.authenticate("user1@test.com", "wrong_password1");
        assertEquals(actualResponse.getCode(), expectedResponse.getCode(), "Unexpected response");
        assertEquals(actualResponse.getMessage(), expectedResponse.getMessage(), "Unexpected response");
    }

    @Test(groups = "negative")
    public void testAuthenticationWithInvalidEmail() {
        Response response = authenticationService.authenticate("user1", "password1");
        assertEquals(response.getCode(), 400, "Response code should be 200");
        assertEquals(response.getMessage(), "Invalid email", "Response message should be \"Invalid email\"");
    }

    @Test(groups = "negative")
    public void testAuthenticationWithEmptyPassword() {
        Response expectedResponse = new Response(400, "Password should not be empty string");
        Response actualResponse = authenticationService.authenticate("user1@test.com", "");
        assertEquals(actualResponse, expectedResponse, "Unexpected response");
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
