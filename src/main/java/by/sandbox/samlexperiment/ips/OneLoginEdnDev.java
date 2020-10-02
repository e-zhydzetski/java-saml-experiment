package by.sandbox.samlexperiment.ips;

import by.sandbox.samlexperiment.domain.IDProvider;
import by.sandbox.samlexperiment.domain.User;

import java.util.List;
import java.util.Map;

public class OneLoginEdnDev implements IDProvider {
    @Override
    public User makeUserFromAttributes(String nameId, Map<String, List<String>> attributes) {
        return new User(
                nameId,
                getFirstAttribute(attributes, "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"),
                getFirstAttribute(attributes, "urn:oid:2.5.4.42"),
                getFirstAttribute(attributes, "urn:oid:2.5.4.4"),
                "",
                null
        );
    }

    private String getFirstAttribute(Map<String, List<String>> attributes, String name) {
        List<String> attr = attributes.get(name);
        if (attr == null || attr.isEmpty())
            throw new IllegalArgumentException("Attribute " + name + " not found");
        return attr.get(0);
    }
}
