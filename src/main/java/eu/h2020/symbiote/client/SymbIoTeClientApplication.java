package eu.h2020.symbiote.client;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class SymbIoTeClientApplication {

    private static Log log = LogFactory.getLog(SymbIoTeClientApplication.class);

    @Value("${symbiote.enabler.core.interface.url}")
    private String symbIoTeCoreUrl;

    public static void main(String[] args) {
		SpringApplication.run(SymbIoTeClientApplication.class, args);
    }

    @Bean(name="symbIoTeCoreUrl")
    public String symbIoTeCoreUrl() {
        return symbIoTeCoreUrl.replaceAll("(/*)$", "");
    }

    @Bean
    public RestTemplate RestTemplate() {
        return new RestTemplate();
    }
}
