package by.sandbox.samlexperiment.ips;

import by.sandbox.samlexperiment.domain.IDProvider;
import by.sandbox.samlexperiment.domain.User;

import java.util.List;
import java.util.Map;

public class SAMLTestID implements IDProvider {
    public User makeUserFromAttributes(String nameId, Map<String, List<String>> attributes) {
        return new User(
                nameId,
                getFirstAttribute(attributes, "urn:oid:0.9.2342.19200300.100.1.3"),
                getFirstAttribute(attributes, "urn:oid:2.5.4.42"),
                getFirstAttribute(attributes, "urn:oid:2.5.4.4"),
                getFirstAttribute(attributes, "https://samltest.id/attributes/role"),
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
