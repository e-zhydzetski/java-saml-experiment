package by.sandbox.samlexperiment.config;

import by.sandbox.samlexperiment.domain.IDProvider;
import by.sandbox.samlexperiment.ips.OneLoginEdnDev;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class Config {
    @Bean
    public IDProvider idProvider() {
        return new OneLoginEdnDev();
    }
}
