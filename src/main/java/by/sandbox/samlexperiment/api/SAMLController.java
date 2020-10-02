package by.sandbox.samlexperiment.api;

import by.sandbox.samlexperiment.domain.IDProvider;
import by.sandbox.samlexperiment.domain.User;
import by.sandbox.samlexperiment.domain.Users;
import com.onelogin.saml2.Auth;
import com.onelogin.saml2.servlet.ServletUtils;
import com.onelogin.saml2.settings.Saml2Settings;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;

import static by.sandbox.samlexperiment.api.AppController.SESSION_TOKEN_COOKIE_NAME;

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
        auth.login(request.getParameter("return"));
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

        log.info("ID: " + auth.getNameId());
        Map<String, List<String>> attributes = auth.getAttributes();
        for (Map.Entry<String, List<String>> attr : attributes.entrySet()) {
            log.info("{}: {}", attr.getKey(), attr.getValue());
        }
        User user = idProvider.makeUserFromAttributes(auth.getNameId(), attributes);
        user = user.withNewSessionToken();
        users.save(user);

        pushUserTokenToCookie(response, user.getSessionToken()); // TODO how do it on API level?

        String relayState = request.getParameter("RelayState");
        if (relayState != null && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request))) {
            response.sendRedirect(relayState);
        }
    }

    // if sessionToken is null - remove cookie
    private void pushUserTokenToCookie(HttpServletResponse response, String sessionToken) {
        Cookie cookie = new Cookie(SESSION_TOKEN_COOKIE_NAME, sessionToken);
        cookie.setMaxAge(sessionToken == null ? 0 : 10 * 60); // 10 minutes, or remove
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }

    @PostMapping(value = "/logout")
    public void logout(@CookieValue(name = SESSION_TOKEN_COOKIE_NAME) String sessionToken,
                       HttpServletRequest request, HttpServletResponse response) throws Exception {
        User user = users.getBySessionToken(sessionToken);
        if (user == null) {
            log.warn("No user for session token '{}'", sessionToken);
            return;
        }

        Auth auth = new Auth(request, response);
        auth.logout(request.getParameter("return"), user.getId(), null);
    }

    @GetMapping(value = "/sls")
    public void sls(@CookieValue(name = SESSION_TOKEN_COOKIE_NAME) String sessionToken,
                    HttpServletRequest request, HttpServletResponse response) throws Exception {
        log.info("SLO for user with session token '{}'", sessionToken);

        Auth auth = new Auth(request, response);
        auth.processSLO();
        List<String> errors = auth.getErrors();
        if (!errors.isEmpty()) {
            throw new IllegalStateException(StringUtils.join(errors, ", "));
        }

        User user = users.getBySessionToken(sessionToken);
        if (user != null) {
            user = user.withRevokedSessionToken();
            users.save(user);
        }
        pushUserTokenToCookie(response, null);

        String relayState = request.getParameter("RelayState");
        if (relayState != null && !relayState.equals(ServletUtils.getSelfRoutedURLNoQuery(request))) {
            response.sendRedirect(relayState);
        }
    }
}
