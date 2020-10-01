package by.sandbox.samlexperiment.domain;

import java.util.List;
import java.util.Map;

public interface IDProvider {
    User makeUserFromAttributes(Map<String, List<String>> attributes);
    String getUserId(Map<String, List<String>> attributes);
}
