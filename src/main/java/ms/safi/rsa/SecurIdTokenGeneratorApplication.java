package ms.safi.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import ms.safi.rsa.securid.Generator;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import static springfox.documentation.builders.PathSelectors.regex;

import java.util.Arrays;
import java.util.List;
import java.util.LinkedList;

@SpringBootApplication
@EnableSwagger2
public class SecurIdTokenGeneratorApplication {

    public static void main(String[] args) {
        List<String> argList = new LinkedList<>(Arrays.asList(args));
        if (argList.contains("--local")) {
            argList.remove("--local");
            Generator.main(argList.toArray(new String[0]));
        } else {
            SpringApplication.run(SecurIdTokenGeneratorApplication.class, args);
        }
    }

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .paths(regex("/token.*"))
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("SecurID Token Generator")
                .description("Generates RSA SecurID Tokens")
                .contact(new Contact("Omeed Safi", "safi.ms", "omeed@safi.ms"))
                .license("MIT License")
                .licenseUrl("https://opensource.org/licenses/MIT")
                .version("1.0")
                .build();
    }
}
