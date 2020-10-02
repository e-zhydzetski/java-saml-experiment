package by.sandbox.samlexperiment.domain;

import java.util.List;
import java.util.Map;

public interface IDProvider {
    User makeUserFromAttributes(String nameId, Map<String, List<String>> attributes);
}
