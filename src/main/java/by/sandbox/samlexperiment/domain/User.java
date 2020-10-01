package by.sandbox.samlexperiment.domain;

import lombok.Value;
import org.apache.commons.lang3.RandomStringUtils;

@Value
public class User {
    String id;
    String email;
    String name;
    String surname;
    String role;

    String sessionToken;

    public User withNewSessionToken() {
        return new User(id, email, name, surname, role, RandomStringUtils.random(32, true, true));
    }

    public User withRevokedSessionToken() {
        return new User(id, email, name, surname, role, null);
    }
}
