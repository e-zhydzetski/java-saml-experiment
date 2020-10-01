package by.sandbox.samlexperiment.api;

import by.sandbox.samlexperiment.domain.User;
import by.sandbox.samlexperiment.domain.Users;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Controller
@RequestMapping("/app")
public class AppController {
    public static final String SESSION_TOKEN_COOKIE_NAME = "sessionToken";

    private final Users users;

    public AppController(Users users) {
        this.users = users;
    }

    @GetMapping(value = "/index")
    public ModelAndView index(@CookieValue(name = SESSION_TOKEN_COOKIE_NAME, required = false) String sessionToken) {
        if (sessionToken == null) {
            log.info("No session cookie -> login");
            return new ModelAndView("redirect:/app/login");
        }
        User user = users.getBySessionToken(sessionToken); // API call to backend
        if (user == null) {
            log.info("No user for session cookie -> login");
            return new ModelAndView("redirect:/app/login");
        }

        Map<String, Object> model = new HashMap<>();
        model.put("id", user.getId());
        model.put("email", user.getEmail());
        model.put("name", user.getName());
        model.put("surname", user.getSurname());
        model.put("role", user.getRole());
        model.put("session_token", user.getSessionToken());

        return new ModelAndView("index", model);
    }

    @GetMapping(value = "/login")
    public ModelAndView login() {
        return new ModelAndView("login");
    }
}
