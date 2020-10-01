package by.sandbox.samlexperiment.api;

import by.sandbox.samlexperiment.domain.IDProvider;
import by.sandbox.samlexperiment.domain.User;
import by.sandbox.samlexperiment.domain.Users;
import com.onelogin.saml2.Auth;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/saml")
public class SAMLController {
    private final Users users;
    private final IDProvider idProvider;

    public SAMLController(Users users, IDProvider idProvider) {
        this.users = users;
        this.idProvider = idProvider;
    }

    @GetMapping(value = "/metadata", produces = "text/xml; charset=UTF-8")
    public String metadata() throws Exception {
        Auth auth = new Auth();
        Saml2Settings settings = auth.getSettings();
        String metadata = settings.getSPMetadata();
        List<String> errors = Saml2Settings.validateMetadata(metadata);
        if (!errors.isEmpty()) {
            throw new IllegalStateException(StringUtils.join(errors, ", "));
        }
        return metadata;
    }

    @PostMapping(value = "/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth(request, response);
        auth.login(request.getParameter("redirect"));
    }

    @PostMapping(value = "/acs")
    public void acs(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth(request, response);
        auth.processResponse();
        if (!auth.isAuthenticated()) {
            throw new IllegalStateException("Not authenticated");
        }

        List<String> errors = auth.getErrors();
        if (!errors.isEmpty()) {
            throw new IllegalStateException(StringUtils.join(errors, ", "));
        }

        Map<String, List<String>> attributes = auth.getAttributes();
        for (Map.Entry<String, List<String>> attr : attributes.entrySet()) {
            log.info("{}: {}", attr.getKey(), attr.getValue());
        }
        User user = idProvider.makeUserFromAttributes(attributes);
        user = user.withNewSessionToken();
        users.save(user);

        pushUserTokenToCookie(response, user.getSessionToken()); // TODO how do it on API level?

        String relayState = request.getParameter("RelayState");
        if (relayState != null && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request))) {
            response.sendRedirect(relayState);
        }
    }

    private void pushUserTokenToCookie(HttpServletResponse response, String sessionToken) {
        Cookie cookie = new Cookie(AppController.SESSION_TOKEN_COOKIE_NAME, sessionToken);
        cookie.setMaxAge(10 * 60); // 10 minutes
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @PostMapping(value = "/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth(request, response);
        auth.logout(request.getParameter("redirect"));
    }

    @PostMapping(value = "/sls")
    public void sls(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Auth auth = new Auth(request, response);
        auth.processSLO();
        List<String> errors = auth.getErrors();
        if (!errors.isEmpty()) {
            throw new IllegalStateException(StringUtils.join(errors, ", "));
        }

        User user = users.get(idProvider.getUserId(auth.getAttributes()));
        user = user.withRevokedSessionToken();
        users.save(user);
    }
}
