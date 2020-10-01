package by.sandbox.samlexperiment.domain;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class Users {
    private final ConcurrentHashMap<String, User> users;

    public Users() {
        users = new ConcurrentHashMap<>();
    }

    public User get(String id) {
        return users.get(id);
    }

    public User getBySessionToken(String sessionToken) {
        for (User user : users.values()) {
            if (sessionToken.equals(user.getSessionToken()))
                return user;
        }
        return null;
    }

    public void save(User user) {
        users.put(user.getId(), user);
    }
}
